use anyhow::{anyhow, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmSubLayerAdd0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FwpmGetAppIdFromFileName0,
    FwpmFreeMemory0, FWPM_ACTION0, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAGS, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0,
    FWP_ACTION_CALLOUT_TERMINATING, FWP_BYTE_BLOB,
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_DATA_TYPE,
    FWP_MATCH_EQUAL, FWPM_CONDITION_ALE_APP_ID,
};

// FWPM_LAYER_ALE_BIND_REDIRECT_V4
const LAYER_ALE_BIND_REDIRECT_V4: GUID = GUID {
    data1: 0x66978CAD,
    data2: 0xC704,
    data3: 0x42AC,
    data4: [0x86, 0x3B, 0xA5, 0x08, 0xD8, 0x36, 0x55, 0x19],
};

// FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V4_SILENT_DROP — built-in callout
// we use this as the redirect action target
const CALLOUT_BIND_REDIRECT_V4: GUID = GUID {
    data1: 0x37a57701,
    data2: 0x5aba,
    data3: 0x4b57,
    data4: [0x93, 0x95, 0xb5, 0x49, 0x90, 0x5f, 0x19, 0x3b],
};

const FWPM_SUBLAYER_UNIVERSAL: GUID = GUID {
    data1: 0xeebecc03,
    data2: 0xced4,
    data3: 0x4380,
    data4: [0x81, 0x9a, 0x27, 0x34, 0x39, 0x7b, 0x2b, 0x74],
};

const FWP_BYTE_BLOB_TYPE: i32 = 12;
const ERROR_SUCCESS: u32 = 0;

pub struct BindRedirectEngine {
    engine: HANDLE,
}

impl BindRedirectEngine {
    pub fn new() -> Result<Self> {
        let mut engine = HANDLE::default();
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };

        let r = unsafe {
            FwpmEngineOpen0(None, 0xa, None, Some(&session), &mut engine)
        };
        if r != ERROR_SUCCESS {
            return Err(anyhow!("FwpmEngineOpen0 failed: {:#010x}", r));
        }

        Ok(Self { engine })
    }

    /// Adds a bind redirect filter for the given exe.
    /// When the exe calls bind(), WFP redirects the source IP to the
    /// Wintun adapter's IP, forcing all its traffic through the tunnel.
    pub fn add_redirect_filter(&self, exe_path: &str, tunnel_ip: &str) -> Result<()> {
        let path_wide = wide(exe_path);
        let mut app_id_ptr: *mut FWP_BYTE_BLOB = std::ptr::null_mut();

        let r = unsafe {
            FwpmGetAppIdFromFileName0(
                windows::core::PCWSTR(path_wide.as_ptr()),
                &mut app_id_ptr,
            )
        };
        if r != ERROR_SUCCESS {
            return Err(anyhow!("FwpmGetAppIdFromFileName0 failed: {:#010x}", r));
        }

        let app_condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_DATA_TYPE(FWP_BYTE_BLOB_TYPE),
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteBlob: app_id_ptr,
                },
            },
        };

        let r = unsafe { FwpmTransactionBegin0(self.engine, 0) };
        if r != ERROR_SUCCESS {
            return Err(anyhow!("FwpmTransactionBegin0 failed: {:#010x}", r));
        }

        unsafe {
            let filter_name = wide(&format!("TunnelboxRedirect-{}", exe_name(exe_path)));
            let mut conditions = [app_condition];

            let filter = FWPM_FILTER0 {
                displayData: FWPM_DISPLAY_DATA0 {
                    name: windows::core::PWSTR(filter_name.as_ptr() as *mut u16),
                    description: windows::core::PWSTR::null(),
                },
                subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
                layerKey: LAYER_ALE_BIND_REDIRECT_V4,
                action: FWPM_ACTION0 {
                    r#type: FWP_ACTION_CALLOUT_TERMINATING,
                    Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0_0 {
                        calloutKey: CALLOUT_BIND_REDIRECT_V4,
                    },
                },
                numFilterConditions: 1,
                filterCondition: conditions.as_mut_ptr(),
                flags: FWPM_FILTER_FLAGS(0),
                ..Default::default()
            };

            let mut filter_id = 0u64;
            let r = FwpmFilterAdd0(self.engine, &filter, None, Some(&mut filter_id));
            if r != ERROR_SUCCESS {
                let _ = FwpmTransactionCommit0(self.engine);
                return Err(anyhow!("FwpmFilterAdd0 (redirect) failed: {:#010x}", r));
            }
        }

        let r = unsafe { FwpmTransactionCommit0(self.engine) };
        if r != ERROR_SUCCESS {
            return Err(anyhow!("FwpmTransactionCommit0 failed: {:#010x}", r));
        }

        unsafe { FwpmFreeMemory0(&mut (app_id_ptr as *mut std::ffi::c_void)) };

        tracing::info!("WFP: bind redirect installed for {} → {}", exe_path, tunnel_ip);
        Ok(())
    }
}

impl Drop for BindRedirectEngine {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn exe_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}
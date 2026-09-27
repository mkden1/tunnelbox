use anyhow::{anyhow, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
use windows::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenCurrentUser, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW, HKEY, KEY_ALL_ACCESS,
    REG_DWORD, REG_SZ, REG_VALUE_TYPE,
};
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::core::PCWSTR;

const INTERNET_SETTINGS: &str =
    "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

/// WinINet proxy state saved at connect time, restored on disconnect.
#[derive(Debug, Default)]
pub struct SavedProxySettings {
    proxy_enable: u32,
    proxy_server: Option<String>,
    proxy_override: Option<String>,
}

/// Saves the current WinINet proxy settings and replaces them with a SOCKS5
/// entry pointing at our tunnel proxy.  Works correctly when called from a
/// LocalSystem service by impersonating the active console user first.
pub fn enable(wintun_ip: &str, port: u16) -> Result<SavedProxySettings> {
    let token = acquire_user_token()?;

    if let Err(e) = unsafe { ImpersonateLoggedOnUser(token) } {
        unsafe { CloseHandle(token).ok() };
        return Err(anyhow!("ImpersonateLoggedOnUser: {e}"));
    }

    let result = (|| {
        let hkey = open_internet_settings()?;
        let out = (|| -> Result<SavedProxySettings> {
            let saved = SavedProxySettings {
                proxy_enable: read_dword(hkey, "ProxyEnable").unwrap_or(0),
                proxy_server: read_string(hkey, "ProxyServer"),
                proxy_override: read_string(hkey, "ProxyOverride"),
            };
            write_dword(hkey, "ProxyEnable", 1)?;
            write_string(hkey, "ProxyServer", &format!("socks={}:{}", wintun_ip, port))?;
            write_string(hkey, "ProxyOverride", "<local>")?;
            Ok(saved)
        })();
        unsafe { RegCloseKey(hkey).ok() };
        out
    })();

    unsafe {
        RevertToSelf().ok();
        CloseHandle(token).ok();
    }

    if result.is_ok() {
        notify_proxy_change();
    }
    result
}

/// Restores the WinINet proxy settings that were saved by [`enable`].
pub fn restore(saved: &SavedProxySettings) -> Result<()> {
    let token = acquire_user_token()?;

    if let Err(e) = unsafe { ImpersonateLoggedOnUser(token) } {
        unsafe { CloseHandle(token).ok() };
        return Err(anyhow!("ImpersonateLoggedOnUser: {e}"));
    }

    let result = (|| {
        let hkey = open_internet_settings()?;
        let out = (|| -> Result<()> {
            write_dword(hkey, "ProxyEnable", saved.proxy_enable)?;
            match &saved.proxy_server {
                Some(s) => write_string(hkey, "ProxyServer", s)?,
                None => delete_value(hkey, "ProxyServer"),
            }
            match &saved.proxy_override {
                Some(s) => write_string(hkey, "ProxyOverride", s)?,
                None => delete_value(hkey, "ProxyOverride"),
            }
            Ok(())
        })();
        unsafe { RegCloseKey(hkey).ok() };
        out
    })();

    unsafe {
        RevertToSelf().ok();
        CloseHandle(token).ok();
    }

    if result.is_ok() {
        notify_proxy_change();
    }
    result
}

// ── internal helpers ──────────────────────────────────────────────────────────

fn acquire_user_token() -> Result<HANDLE> {
    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == 0xFFFF_FFFF {
        return Err(anyhow!("No active console session"));
    }
    let mut token = HANDLE::default();
    unsafe { WTSQueryUserToken(session_id, &mut token) }
        .map_err(|e| anyhow!("WTSQueryUserToken: {e}"))?;
    Ok(token)
}

fn open_internet_settings() -> Result<HKEY> {
    // RegOpenCurrentUser uses the thread's current impersonation token,
    // giving us the logged-in user's HKCU even when running as SYSTEM.
    let mut hkcu = HKEY::default();
    unsafe { RegOpenCurrentUser(KEY_ALL_ACCESS.0, &mut hkcu) }
        .map_err(|e| anyhow!("RegOpenCurrentUser: {e}"))?;

    let subkey = wide(INTERNET_SETTINGS);
    let mut hkey = HKEY::default();
    let result = unsafe {
        RegOpenKeyExW(hkcu, PCWSTR(subkey.as_ptr()), 0, KEY_ALL_ACCESS, &mut hkey)
    };
    unsafe { RegCloseKey(hkcu).ok() };
    result.map_err(|e| anyhow!("RegOpenKeyExW(Internet Settings): {e}"))?;
    Ok(hkey)
}

fn read_dword(hkey: HKEY, name: &str) -> Option<u32> {
    let name_w = wide(name);
    let mut val_type = REG_VALUE_TYPE::default();
    let mut data = 0u32;
    let mut size = 4u32;
    let ok = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut val_type),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut size),
        )
    }
    .is_ok();
    if ok && val_type == REG_DWORD { Some(data) } else { None }
}

fn read_string(hkey: HKEY, name: &str) -> Option<String> {
    let name_w = wide(name);
    let mut val_type = REG_VALUE_TYPE::default();
    let mut size = 0u32;

    // First call: get required buffer size
    let _ = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut val_type),
            None,
            Some(&mut size),
        )
    };
    if size == 0 {
        return None;
    }

    let mut buf = vec![0u8; size as usize];
    let ok = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut val_type),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        )
    }
    .is_ok();
    if !ok {
        return None;
    }

    let words: Vec<u16> = buf
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    Some(String::from_utf16_lossy(&words).trim_end_matches('\0').to_string())
}

fn write_dword(hkey: HKEY, name: &str, value: u32) -> Result<()> {
    let name_w = wide(name);
    let bytes = value.to_le_bytes();
    unsafe { RegSetValueExW(hkey, PCWSTR(name_w.as_ptr()), 0, REG_DWORD, Some(&bytes)) }
        .map_err(|e| anyhow!("write_dword({name}): {e}"))
}

fn write_string(hkey: HKEY, name: &str, value: &str) -> Result<()> {
    let name_w = wide(name);
    let value_w: Vec<u16> = OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let bytes = unsafe {
        std::slice::from_raw_parts(value_w.as_ptr() as *const u8, value_w.len() * 2)
    };
    unsafe { RegSetValueExW(hkey, PCWSTR(name_w.as_ptr()), 0, REG_SZ, Some(bytes)) }
        .map_err(|e| anyhow!("write_string({name}): {e}"))
}

fn delete_value(hkey: HKEY, name: &str) {
    let name_w = wide(name);
    unsafe { RegDeleteValueW(hkey, PCWSTR(name_w.as_ptr())).ok() };
}

/// Broadcasts WM_SETTINGCHANGE so already-running apps reload proxy config.
///
/// Note: from Session 0 this only reaches Session 0 windows. Interactive-session
/// apps (Firefox, Chrome) pick up the registry change when launched, or on their
/// next internal proxy refresh cycle.
fn notify_proxy_change() {
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };
    let param = wide(INTERNET_SETTINGS);
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            WPARAM(0),
            LPARAM(param.as_ptr() as isize),
            SMTO_ABORTIFHUNG,
            2000,
            None,
        );
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

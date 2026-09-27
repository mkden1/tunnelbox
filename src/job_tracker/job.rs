use anyhow::{anyhow, Result};
use std::ffi::{c_void, OsStr};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicProcessIdList,
    JobObjectExtendedLimitInformation, OpenJobObjectW, QueryInformationJobObject,
    SetInformationJobObject, JOBOBJECT_BASIC_PROCESS_ID_LIST,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

/// `JOB_OBJECT_QUERY` access right (winnt.h) — read-only access to the job.
const JOB_OBJECT_QUERY: u32 = 0x0004;
use windows::Win32::System::Threading::{
    CreateProcessW, GetCurrentProcessId, ResumeThread, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows::Win32::System::Environment::{
    CreateEnvironmentBlock, DestroyEnvironmentBlock, FreeEnvironmentStringsW,
    GetEnvironmentStringsW,
};
use windows::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSGetActiveConsoleSessionId, WTSQueryUserToken,
};

/// Returns the Job Object name for a profile. Must match everywhere the job is
/// created or opened (the PID refresher opens it by name).
pub fn job_object_name(profile_id: &str) -> String {
    format!("TunnelboxJob-{}", &profile_id[..8])
}

pub struct JobObject {
    handle: HANDLE,
    pub profile_id: String,
    pub processes: Vec<ProcessEntry>,
}

pub struct ProcessEntry {
    pub pid: u32,
    pub exe: String,
    handle: HANDLE,
}

impl JobObject {
    /// Creates a new Job Object for a profile.
    pub fn new(profile_id: &str) -> Result<Self> {
        let name = wide(&job_object_name(profile_id));

        let handle = unsafe {
            CreateJobObjectW(None, windows::core::PCWSTR(name.as_ptr()))
        }
        .map_err(|e| anyhow!("Failed to create Job Object: {e}"))?;

        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(|e| anyhow!("Failed to set job limits: {e}"))?;

        Ok(Self {
            handle,
            profile_id: profile_id.to_string(),
            processes: Vec::new(),
        })
    }

    /// Spawns a process inside this Job Object.
    ///
    /// If the daemon is in Session 0 (running as a Windows Service), uses
    /// `WTSQueryUserToken` + `CreateProcessAsUserW` to spawn in the active
    /// interactive session so the process can show a window. Falls back to plain
    /// `CreateProcessW` when already in an interactive session.
    ///
    /// The process is placed in the job while suspended, so it is a tracked
    /// target of the WinDivert flow tracker before it can make any network call.
    pub fn spawn(&mut self, exe_path: &str, args: &[String]) -> Result<u32> {
        let cmd = if args.is_empty() {
            format!("\"{}\"", exe_path)
        } else {
            format!("\"{}\" {}", exe_path, args.join(" "))
        };
        let mut cmd_wide = wide(&cmd);
        let exe_wide = wide(exe_path);

        // Detect session: services run in Session 0 and can't show UI there.
        let mut our_session: u32 = 0;
        let in_service = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut our_session) }
            .is_ok()
            && our_session == 0;

        let (proc_handle, thread_handle, pid) = if in_service {
            tracing::debug!("Daemon is in Session 0 — spawning {} in user session", exe_path);
            spawn_in_user_session(exe_path, &mut cmd_wide)?
        } else {
            spawn_direct(&exe_wide, &mut cmd_wide)?
        };

        // Assign to job before the thread runs — works cross-session because job
        // handles are kernel objects.
        unsafe {
            AssignProcessToJobObject(self.handle, proc_handle)
        }
        .map_err(|e| {
            unsafe {
                CloseHandle(proc_handle).ok();
                CloseHandle(thread_handle).ok();
            }
            anyhow!("Failed to assign process to job: {e}")
        })?;

        unsafe { ResumeThread(thread_handle) };
        unsafe { CloseHandle(thread_handle).ok() };

        self.processes.push(ProcessEntry {
            pid,
            exe: exe_path.to_string(),
            handle: proc_handle,
        });

        tracing::info!(
            "Spawned {} (pid {}) in job for profile {}",
            exe_path,
            pid,
            self.profile_id
        );

        Ok(pid)
    }

    /// Returns the PIDs of the processes this instance launched directly.
    /// (Descendants are covered by [`query_job_pids_by_name`].)
    pub fn pids(&self) -> Vec<u32> {
        self.processes.iter().map(|p| p.pid).collect()
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        for proc in &self.processes {
            unsafe { CloseHandle(proc.handle).ok() };
        }
        unsafe { CloseHandle(self.handle).ok() };
        tracing::info!("Job Object closed for profile {}", self.profile_id);
    }
}

/// Returns all PIDs currently assigned to the named Job Object, including
/// descendant processes. Used by the divert engine to keep its target set live.
/// Returns an empty vec if the job can't be opened/queried.
pub fn query_job_pids_by_name(job_name: &str) -> Vec<u32> {
    let name = wide(job_name);
    let job = match unsafe {
        OpenJobObjectW(JOB_OBJECT_QUERY, false, windows::core::PCWSTR(name.as_ptr()))
    } {
        Ok(h) if !h.is_invalid() => h,
        _ => return Vec::new(),
    };

    // Header struct already contains room for one PID; reserve space for CAP.
    const CAP: usize = 2048;
    let buf_len = size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() + (CAP - 1) * size_of::<usize>();
    let mut buf = vec![0u8; buf_len];
    let mut ret_len = 0u32;

    let result = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicProcessIdList,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            Some(&mut ret_len),
        )
    };

    let pids = if result.is_ok() {
        let header = unsafe { &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST) };
        let n = header.NumberOfProcessIdsInList as usize;
        let list_ptr = std::ptr::addr_of!(header.ProcessIdList) as *const usize;
        (0..n)
            .map(|i| unsafe { *list_ptr.add(i) } as u32)
            .collect()
    } else {
        Vec::new()
    };

    unsafe { CloseHandle(job).ok() };
    pids
}

/// Spawns a suspended process using the active interactive user's token.
/// Required when the daemon is in Session 0 so the spawned app can show a window.
fn spawn_in_user_session(
    exe_path: &str,
    cmd_wide: &mut [u16],
) -> Result<(HANDLE, HANDLE, u32)> {
    use windows::Win32::System::Threading::CreateProcessAsUserW;

    let session_id = unsafe { WTSGetActiveConsoleSessionId() };
    if session_id == 0xFFFF_FFFF {
        return Err(anyhow!("WTSGetActiveConsoleSessionId: no active console session"));
    }

    let mut user_token = HANDLE::default();
    unsafe { WTSQueryUserToken(session_id, &mut user_token) }.map_err(|e| {
        anyhow!(
            "WTSQueryUserToken(session {session_id}): {e}\n\
             The service must run as LocalSystem (needs SE_TCB_PRIVILEGE)"
        )
    })?;

    let result = (|| -> Result<(HANDLE, HANDLE, u32)> {
        let env_block = build_env_block_from_token(user_token)?;

        let exe_wide = wide(exe_path);
        let mut desktop = wide("WinSta0\\Default");

        let startup_info = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            lpDesktop: windows::core::PWSTR(desktop.as_mut_ptr()),
            ..Default::default()
        };
        let mut proc_info = PROCESS_INFORMATION::default();

        unsafe {
            CreateProcessAsUserW(
                user_token,
                windows::core::PCWSTR(exe_wide.as_ptr()),
                windows::core::PWSTR(cmd_wide.as_mut_ptr()),
                None,
                None,
                false,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                Some(env_block.as_ptr() as *const c_void),
                windows::core::PCWSTR(std::ptr::null()),
                &startup_info,
                &mut proc_info,
            )
        }
        .map_err(|e| anyhow!("CreateProcessAsUserW({exe_path}): {e}"))?;

        Ok((proc_info.hProcess, proc_info.hThread, proc_info.dwProcessId))
    })();

    unsafe { CloseHandle(user_token).ok() };
    result
}

/// Spawns a suspended process in the current session (interactive / dev mode).
fn spawn_direct(exe_wide: &[u16], cmd_wide: &mut [u16]) -> Result<(HANDLE, HANDLE, u32)> {
    let startup_info = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut proc_info = PROCESS_INFORMATION::default();

    unsafe {
        CreateProcessW(
            windows::core::PCWSTR(exe_wide.as_ptr()),
            windows::core::PWSTR(cmd_wide.as_mut_ptr()),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(CREATE_SUSPENDED.0),
            None,
            None,
            &startup_info,
            &mut proc_info,
        )
    }
    .map_err(|e| anyhow!("CreateProcessW: {e}"))?;

    Ok((proc_info.hProcess, proc_info.hThread, proc_info.dwProcessId))
}

/// Builds a UTF-16 env block for `CreateProcessAsUserW` from the user's profile
/// environment (via their token).
fn build_env_block_from_token(token: HANDLE) -> Result<Vec<u16>> {
    let mut block: Vec<u16> = Vec::new();

    let mut env_ptr: *mut c_void = std::ptr::null_mut();
    unsafe { CreateEnvironmentBlock(&mut env_ptr, token, false) }
        .map_err(|e| anyhow!("CreateEnvironmentBlock: {e}"))?;

    unsafe {
        let mut ptr = env_ptr as *const u16;
        loop {
            if *ptr == 0 {
                block.push(0);
                ptr = ptr.add(1);
                if *ptr == 0 {
                    break;
                }
            } else {
                block.push(*ptr);
                ptr = ptr.add(1);
            }
        }
        DestroyEnvironmentBlock(env_ptr).ok();
    }

    block.push(0); // final null (double-null termination complete)
    Ok(block)
}

/// Builds a UTF-16 env block inheriting the daemon's own environment. Retained
/// for potential interactive use; currently unused by the default spawn paths.
#[allow(dead_code)]
fn build_env_block_from_daemon() -> Vec<u16> {
    let mut block: Vec<u16> = Vec::new();

    unsafe {
        let env_ptr = GetEnvironmentStringsW();
        if !env_ptr.is_null() {
            let mut ptr = env_ptr.0 as *const u16;
            loop {
                if *ptr == 0 {
                    block.push(0);
                    ptr = ptr.add(1);
                    if *ptr == 0 {
                        break;
                    }
                } else {
                    block.push(*ptr);
                    ptr = ptr.add(1);
                }
            }
            FreeEnvironmentStringsW(windows::core::PCWSTR(env_ptr.0 as *const u16)).ok();
        }
    }

    block.push(0);
    block
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

use anyhow::{anyhow, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread,
    PROCESS_INFORMATION, STARTUPINFOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
};
use windows::Win32::System::Environment::{
    GetEnvironmentStringsW, FreeEnvironmentStringsW,
};

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
        let name = wide(&format!("TunnelboxJob-{}", &profile_id[..8]));

        let handle = unsafe {
            CreateJobObjectW(None, windows::core::PCWSTR(name.as_ptr()))
        }
        .map_err(|e| anyhow!("Failed to create Job Object: {e}"))?;

        // Set KILL_ON_JOB_CLOSE so all processes are killed when handle closes
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
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
    /// The process is created suspended, assigned to the job,
    /// then resumed — this ensures it's in the job before any
    /// network activity can occur.
    pub fn spawn(&mut self, exe_path: &str, args: &[String], proxy_addr: Option<&str>) -> Result<u32> {
        let cmd = if args.is_empty() {
            format!("\"{}\"", exe_path)
        } else {
            format!("\"{}\" {}", exe_path, args.join(" "))
        };

        let mut cmd_wide = wide(&cmd);
        let exe_wide = wide(exe_path);

        // Build environment block with proxy settings if provided
        let env_block = proxy_addr.map(|addr| {
            build_env_block(&[
                ("ALL_PROXY",   addr),
                ("all_proxy",   addr),
                ("HTTPS_PROXY", addr),
                ("https_proxy", addr),
                ("HTTP_PROXY",  addr),
                ("http_proxy",  addr),
            ])
        });

        let startup_info = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process_info = PROCESS_INFORMATION::default();

        let flags = CREATE_SUSPENDED | if env_block.is_some() {
            CREATE_UNICODE_ENVIRONMENT
        } else {
            windows::Win32::System::Threading::PROCESS_CREATION_FLAGS(0)
        };

        unsafe {
            CreateProcessW(
                windows::core::PCWSTR(exe_wide.as_ptr()),
                windows::core::PWSTR(cmd_wide.as_mut_ptr()),
                None,
                None,
                false,
                flags,
                env_block.as_ref().map(|e| e.as_ptr() as *const std::ffi::c_void),
                None,
                &startup_info,
                &mut process_info,
            )
        }
        .map_err(|e| anyhow!("Failed to create process {exe_path}: {e}"))?;

        let pid = process_info.dwProcessId;

        unsafe {
            AssignProcessToJobObject(self.handle, process_info.hProcess)
        }
        .map_err(|e| {
            unsafe {
                CloseHandle(process_info.hProcess).ok();
                CloseHandle(process_info.hThread).ok();
            }
            anyhow!("Failed to assign process to job: {e}")
        })?;

        unsafe { ResumeThread(process_info.hThread) };
        unsafe { CloseHandle(process_info.hThread).ok() };

        self.processes.push(ProcessEntry {
            pid,
            exe: exe_path.to_string(),
            handle: process_info.hProcess,
        });

        tracing::info!("Spawned {} (pid {}) in job for profile {}",
            exe_path, pid, self.profile_id);

        Ok(pid)
    }
    

    /// Returns the PIDs of all processes currently in this job.
    pub fn pids(&self) -> Vec<u32> {
        self.processes.iter().map(|p| p.pid).collect()
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        // Closing the job handle kills all processes in it
        // (because of JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        // and releases the job object
        for proc in &self.processes {
            unsafe { CloseHandle(proc.handle).ok() };
        }
        unsafe { CloseHandle(self.handle).ok() };
        tracing::info!("Job Object closed for profile {}", self.profile_id);
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Builds a UTF-16 environment block for CreateProcessW.
/// Inherits the current process environment and prepends the given vars.
/// Format: KEY=VALUE\0KEY=VALUE\0\0 (UTF-16, double null terminated)
fn build_env_block(extra_vars: &[(&str, &str)]) -> Vec<u16> {
    let mut block: Vec<u16> = Vec::new();

    // Add our extra vars first so they take precedence
    for (key, val) in extra_vars {
        let entry = format!("{}={}", key, val);
        block.extend(entry.encode_utf16());
        block.push(0);
    }

    // Inherit current process environment
    unsafe {
        let env_ptr = GetEnvironmentStringsW();
        if !env_ptr.is_null() {
            let mut ptr = env_ptr.0 as *const u16;
            // Walk the double-null-terminated UTF-16 block
            loop {
                if *ptr == 0 {
                    block.push(0); // include the null terminator for this entry
                    ptr = ptr.add(1);
                    if *ptr == 0 {
                        // Double null — end of block
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

    block.push(0); // final null terminator
    block
}


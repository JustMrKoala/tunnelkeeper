//! Windows services through the service control manager.
//!
//! The service launches cloudflared directly as LocalService. Tested on a real
//! SCM on 2026-11-05: a custom name works, because the dispatch name is ignored
//! for own process services, and a per service SID can own the token ACL.

use std::ffi::c_void;
use std::path::Path;
use std::process::Command;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS, ERROR_SERVICE_NOT_ACTIVE,
    GetLastError,
};
use windows_sys::Win32::System::Services::*;

use super::{ServiceInfo, ServiceManager, ServiceSpec, ServiceState};
use crate::error::{Error, Result};
use crate::paths::Paths;

const SID_SYSTEM: &str = "*S-1-5-18";
const SID_ADMINS: &str = "*S-1-5-32-544";
const SID_USERS: &str = "*S-1-5-32-545";
const START_TIMEOUT: Duration = Duration::from_secs(45);
/// cloudflared drains connections on stop, which takes a while.
const STOP_TIMEOUT: Duration = Duration::from_secs(60);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

fn last_error(action: &str) -> Error {
    let code = unsafe { GetLastError() };
    if code == ERROR_ACCESS_DENIED {
        Error::Elevation(format!("{action}: access denied, administrator rights are needed"))
    } else {
        Error::Service(format!("{action}: Windows error {code}"))
    }
}

fn open_manager(access: u32) -> Result<Handle> {
    let h = unsafe { OpenSCManagerW(null(), null(), access) };
    if h.is_null() { Err(last_error("open service manager")) } else { Ok(Handle(h)) }
}

fn open_service(manager: &Handle, name: &str, access: u32) -> Result<Option<Handle>> {
    let n = wide(name);
    let h = unsafe { OpenServiceW(manager.0, n.as_ptr(), access) };
    if !h.is_null() {
        return Ok(Some(Handle(h)));
    }
    if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
        return Ok(None);
    }
    Err(last_error(&format!("open service {name}")))
}

fn quote(s: &str) -> String {
    if s.contains(' ') { format!("\"{s}\"") } else { s.to_string() }
}

/// Builds the command line stored in the service entry.
pub fn command_line(binary: &Path, args: &[String]) -> String {
    let mut line = format!("\"{}\"", binary.display());
    for a in args {
        line.push(' ');
        line.push_str(&quote(a));
    }
    line
}

fn status_of(service: &Handle) -> Result<SERVICE_STATUS_PROCESS> {
    unsafe {
        let mut status: SERVICE_STATUS_PROCESS = std::mem::zeroed();
        let mut needed = 0u32;
        let ok = QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            &mut status as *mut _ as *mut u8,
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        );
        if ok == 0 { Err(last_error("query service status")) } else { Ok(status) }
    }
}

fn state_of(raw: u32) -> ServiceState {
    match raw {
        SERVICE_STOPPED => ServiceState::Stopped,
        SERVICE_START_PENDING => ServiceState::Starting,
        SERVICE_RUNNING => ServiceState::Running,
        SERVICE_STOP_PENDING => ServiceState::Stopping,
        _ => ServiceState::Other,
    }
}

fn configured_command(service: &Handle) -> Option<String> {
    unsafe {
        let mut needed = 0u32;
        QueryServiceConfigW(service.0, null_mut(), 0, &mut needed);
        if needed == 0 {
            return None;
        }
        // u64 storage keeps the buffer aligned for the struct.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        let config = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        if QueryServiceConfigW(service.0, config, needed, &mut needed) == 0 {
            return None;
        }
        Some(from_wide((*config).lpBinaryPathName))
    }
}

fn wait_for(service: &Handle, wanted: u32, timeout: Duration) -> Result<bool> {
    let start = Instant::now();
    loop {
        if status_of(service)?.dwCurrentState == wanted {
            return Ok(true);
        }
        if start.elapsed() > timeout {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn set_config2(service: &Handle, level: u32, data: *mut c_void, what: &str) -> Result<()> {
    if unsafe { ChangeServiceConfig2W(service.0, level, data) } == 0 {
        return Err(last_error(what));
    }
    Ok(())
}

/// Restart after 5 s, 5 s, then every 30 s, including after a non zero exit.
fn configure_recovery(service: &Handle) -> Result<()> {
    let mut actions = [
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 5_000 },
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 5_000 },
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 30_000 },
    ];
    let mut failure = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 86_400,
        lpRebootMsg: null_mut(),
        lpCommand: null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    set_config2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &mut failure as *mut _ as *mut c_void, "set recovery actions")?;
    let mut flag = SERVICE_FAILURE_ACTIONS_FLAG { fFailureActionsOnNonCrashFailures: 1 };
    set_config2(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &mut flag as *mut _ as *mut c_void, "set recovery flag")
}

fn icacls(path: &Path, args: &[&str]) -> Result<()> {
    let system_root = std::env::var_os("SystemRoot").ok_or_else(|| Error::Service("SystemRoot is not set".into()))?;
    let tool = Path::new(&system_root).join("System32").join("icacls.exe");
    let out = Command::new(tool).arg(path).args(args).output().map_err(|e| Error::io("run icacls", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Error::Service(format!(
            "setting permissions on {} failed: {}",
            path.display(),
            String::from_utf8_lossy(&out.stdout).trim()
        )))
    }
}

fn grant(sid: &str, rights: &str) -> String {
    format!("{sid}:{rights}")
}

pub struct WindowsServices;

impl ServiceManager for WindowsServices {
    fn query(&self, name: &str) -> Result<ServiceInfo> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let Some(service) = open_service(&manager, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)? else {
            return Ok(ServiceInfo::missing(name));
        };
        let status = status_of(&service)?;
        Ok(ServiceInfo {
            name: name.to_string(),
            state: state_of(status.dwCurrentState),
            pid: (status.dwProcessId != 0).then_some(status.dwProcessId),
            command_line: configured_command(&service),
            exit_code: Some(status.dwWin32ExitCode),
        })
    }

    fn prepare_machine_dirs(&self, paths: &Paths) -> Result<()> {
        for dir in [&paths.bin_dir, &paths.token_dir, &paths.log_root] {
            std::fs::create_dir_all(dir).map_err(|e| Error::io(format!("create {}", dir.display()), e))?;
        }
        // ProgramData lets users create folders, so a planted folder must lose
        // its owner and permissions before we trust it.
        icacls(&paths.machine_dir, &["/setowner", SID_ADMINS, "/T", "/C"])?;
        let (system, admins, users) =
            (grant(SID_SYSTEM, "(OI)(CI)F"), grant(SID_ADMINS, "(OI)(CI)F"), grant(SID_USERS, "(OI)(CI)RX"));
        icacls(&paths.machine_dir, &["/inheritance:r", "/grant:r", &system, &admins, &users])?;
        // Users may list this folder, so unelevated checks can see whether a
        // token exists. The grant has no inheritance flags, so it does not
        // reach the token files, and those stay unreadable.
        icacls(&paths.token_dir, &["/inheritance:r", "/grant:r", &system, &admins, &grant(SID_USERS, "RX")])
    }

    fn install(&self, spec: &ServiceSpec) -> Result<()> {
        let manager = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
        let name = wide(&spec.name);
        let display = wide(&spec.display_name);
        let command = wide(&command_line(&spec.binary, &spec.args));
        let account = wide("NT AUTHORITY\\LocalService");
        let created = unsafe {
            CreateServiceW(
                manager.0,
                name.as_ptr(),
                display.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                command.as_ptr(),
                null(),
                null_mut(),
                null(),
                account.as_ptr(),
                null(),
            )
        };
        let service = if !created.is_null() {
            Handle(created)
        } else if unsafe { GetLastError() } == ERROR_SERVICE_EXISTS {
            let existing = open_service(&manager, &spec.name, SERVICE_ALL_ACCESS)?
                .ok_or_else(|| Error::Service(format!("service {} vanished during install", spec.name)))?;
            let ok = unsafe {
                ChangeServiceConfigW(
                    existing.0,
                    SERVICE_NO_CHANGE,
                    SERVICE_AUTO_START,
                    SERVICE_NO_CHANGE,
                    command.as_ptr(),
                    null(),
                    null_mut(),
                    null(),
                    account.as_ptr(),
                    null(),
                    display.as_ptr(),
                )
            };
            if ok == 0 {
                return Err(last_error("update service"));
            }
            existing
        } else {
            return Err(last_error("create service"));
        };

        let mut description_text = wide("Keeps a Cloudflare Tunnel running. Managed by tunnelkeeper.");
        let mut description = SERVICE_DESCRIPTIONW { lpDescription: description_text.as_mut_ptr() };
        set_config2(&service, SERVICE_CONFIG_DESCRIPTION, &mut description as *mut _ as *mut c_void, "set description")?;
        configure_recovery(&service)?;
        let mut sid = SERVICE_SID_INFO { dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED };
        set_config2(&service, SERVICE_CONFIG_SERVICE_SID_INFO, &mut sid as *mut _ as *mut c_void, "set service SID")?;

        // The token is readable by this service alone, not by every service
        // running as LocalService.
        let service_sid = format!("NT SERVICE\\{}", spec.name);
        std::fs::create_dir_all(&spec.log_dir).map_err(|e| Error::io("create log folder", e))?;
        icacls(&spec.token_path, &["/inheritance:r", "/grant:r", &grant(SID_SYSTEM, "F"), &grant(SID_ADMINS, "F"), &grant(&service_sid, "R")])?;
        icacls(&spec.log_dir, &["/grant", &grant(&service_sid, "(OI)(CI)M")])
    }

    fn start(&self, name: &str) -> Result<()> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = open_service(&manager, name, SERVICE_START | SERVICE_QUERY_STATUS)?
            .ok_or_else(|| Error::NotFound(format!("service {name}")))?;
        if unsafe { StartServiceW(service.0, 0, null()) } == 0 && unsafe { GetLastError() } != ERROR_SERVICE_ALREADY_RUNNING {
            return Err(last_error(&format!("start {name}")));
        }
        if wait_for(&service, SERVICE_RUNNING, START_TIMEOUT)? {
            Ok(())
        } else {
            Err(Error::Service(format!("{name} did not reach the running state in time")))
        }
    }

    fn stop(&self, name: &str) -> Result<()> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let service = open_service(&manager, name, SERVICE_STOP | SERVICE_QUERY_STATUS)?
            .ok_or_else(|| Error::NotFound(format!("service {name}")))?;
        let mut status: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } == 0
            && unsafe { GetLastError() } != ERROR_SERVICE_NOT_ACTIVE
        {
            return Err(last_error(&format!("stop {name}")));
        }
        if wait_for(&service, SERVICE_STOPPED, STOP_TIMEOUT)? {
            Ok(())
        } else {
            Err(Error::Service(format!("{name} did not stop in time")))
        }
    }

    fn uninstall(&self, name: &str) -> Result<()> {
        let manager = open_manager(SC_MANAGER_CONNECT)?;
        let Some(service) = open_service(&manager, name, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE_ACCESS)? else {
            return Ok(());
        };
        if status_of(&service)?.dwCurrentState != SERVICE_STOPPED {
            self.stop(name)?;
        }
        if unsafe { DeleteService(service.0) } == 0 {
            return Err(last_error(&format!("delete {name}")));
        }
        Ok(())
    }
}

/// The standard DELETE access right.
const DELETE_ACCESS: u32 = 0x0001_0000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_quotes_paths_with_spaces() {
        let line = command_line(Path::new(r"C:\Program Data\cf.exe"), &["run".into(), r"C:\a b\c".into()]);
        assert_eq!(line, r#""C:\Program Data\cf.exe" run "C:\a b\c""#);
    }

    #[test]
    fn query_of_missing_service_works_without_elevation() {
        let info = WindowsServices.query("tunnelkeeper-does-not-exist").unwrap();
        assert_eq!(info.state, ServiceState::Missing);
    }

    #[test]
    fn query_of_real_service_works_without_elevation() {
        let info = WindowsServices.query("EventLog").unwrap();
        assert_eq!(info.state, ServiceState::Running);
        assert!(info.command_line.unwrap().to_lowercase().contains("svchost"));
    }
}

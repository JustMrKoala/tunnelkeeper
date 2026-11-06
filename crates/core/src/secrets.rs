//! Storage for the Cloudflare API token. Tunnel tokens are handled elsewhere,
//! because a service account cannot read a user's credential store.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::paths::Paths;
use crate::secret::Secret;

pub const API_TOKEN_KEY: &str = "tunnelkeeper/api-token";

pub trait SecretStore: Send {
    fn get(&self, key: &str) -> Result<Option<Secret>>;
    fn set(&self, key: &str, value: &Secret) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
    fn backend(&self) -> &'static str;
}

#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<String, Secret>>);

impl SecretStore for MemoryStore {
    fn get(&self, key: &str) -> Result<Option<Secret>> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn set(&self, key: &str, value: &Secret) -> Result<()> {
        self.0.lock().unwrap().insert(key.to_string(), value.clone());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
    fn backend(&self) -> &'static str {
        "memory"
    }
}

/// Owner only file. The fallback where no credential store is available.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn new(dir: PathBuf) -> Self {
        FileStore { dir }
    }
    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(key.replace('/', "_"))
    }
}

impl SecretStore for FileStore {
    fn get(&self, key: &str) -> Result<Option<Secret>> {
        match std::fs::read_to_string(self.path(key)) {
            Ok(v) => Ok(Some(Secret::new(v))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::io("read secret file", e)),
        }
    }

    fn set(&self, key: &str, value: &Secret) -> Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(&self.dir).map_err(|e| Error::io("create secret folder", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| Error::io("protect secret folder", e))?;
        }
        let path = self.path(key);
        let _ = std::fs::remove_file(&path);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).map_err(|e| Error::io("create secret file", e))?;
        f.write_all(value.expose().as_bytes()).map_err(|e| Error::io("write secret file", e))
    }

    fn delete(&self, key: &str) -> Result<()> {
        match std::fs::remove_file(self.path(key)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Error::io("delete secret file", e)),
            _ => Ok(()),
        }
    }

    fn backend(&self) -> &'static str {
        "owner only file"
    }
}

#[cfg(windows)]
mod wincred {
    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW, CredWriteW,
    };

    use super::*;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub struct WinCredStore;

    impl SecretStore for WinCredStore {
        fn get(&self, key: &str) -> Result<Option<Secret>> {
            let target = wide(key);
            let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
            unsafe {
                if CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) == 0 {
                    let code = GetLastError();
                    return if code == ERROR_NOT_FOUND {
                        Ok(None)
                    } else {
                        Err(Error::Secret(format!("reading Credential Manager failed, code {code}")))
                    };
                }
                let blob = std::slice::from_raw_parts((*cred).CredentialBlob, (*cred).CredentialBlobSize as usize);
                let value = String::from_utf8(blob.to_vec());
                CredFree(cred as *const _);
                value.map(|v| Some(Secret::new(v))).map_err(|_| Error::Secret("stored token is not valid text".into()))
            }
        }

        fn set(&self, key: &str, value: &Secret) -> Result<()> {
            let target = wide(key);
            let user = wide("tunnelkeeper");
            let mut blob = value.expose().as_bytes().to_vec();
            unsafe {
                let mut cred: CREDENTIALW = std::mem::zeroed();
                cred.Type = CRED_TYPE_GENERIC;
                cred.TargetName = target.as_ptr() as *mut u16;
                cred.UserName = user.as_ptr() as *mut u16;
                cred.CredentialBlob = blob.as_mut_ptr();
                cred.CredentialBlobSize = blob.len() as u32;
                cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
                let ok = CredWriteW(&cred, 0);
                blob.iter_mut().for_each(|b| std::ptr::write_volatile(b, 0));
                if ok == 0 {
                    return Err(Error::Secret(format!("writing Credential Manager failed, code {}", GetLastError())));
                }
            }
            Ok(())
        }

        fn delete(&self, key: &str) -> Result<()> {
            let target = wide(key);
            unsafe {
                if CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) == 0 {
                    let code = GetLastError();
                    if code != ERROR_NOT_FOUND {
                        return Err(Error::Secret(format!("deleting from Credential Manager failed, code {code}")));
                    }
                }
            }
            Ok(())
        }

        fn backend(&self) -> &'static str {
            "Windows Credential Manager"
        }
    }
}

#[cfg(windows)]
pub use wincred::WinCredStore;

#[cfg(windows)]
pub fn platform_store(_paths: &Paths) -> Box<dyn SecretStore> {
    Box::new(WinCredStore)
}

/// Secret Service through the `secret-tool` program, which avoids a D-Bus
/// library. Headless machines usually have no keyring running, so every
/// operation falls back to the owner only file.
#[cfg(not(windows))]
pub struct SecretToolStore {
    fallback: FileStore,
}

#[cfg(not(windows))]
impl SecretToolStore {
    fn attrs(key: &str) -> [&str; 4] {
        ["service", "tunnelkeeper", "key", key]
    }

    fn try_store(key: &str, value: &Secret) -> bool {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let child = Command::new("secret-tool")
            .args(["store", "--label=tunnelkeeper"])
            .args(Self::attrs(key))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(mut child) = child else { return false };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(value.expose().as_bytes());
        }
        child.wait().is_ok_and(|s| s.success())
    }
}

#[cfg(not(windows))]
impl SecretStore for SecretToolStore {
    fn get(&self, key: &str) -> Result<Option<Secret>> {
        let out = std::process::Command::new("secret-tool").arg("lookup").args(Self::attrs(key)).output();
        if let Ok(o) = out
            && o.status.success()
            && !o.stdout.is_empty()
        {
            return Ok(Some(Secret::new(String::from_utf8_lossy(&o.stdout).trim_end().to_string())));
        }
        self.fallback.get(key)
    }

    fn set(&self, key: &str, value: &Secret) -> Result<()> {
        if Self::try_store(key, value) {
            return self.fallback.delete(key);
        }
        self.fallback.set(key, value)
    }

    fn delete(&self, key: &str) -> Result<()> {
        let _ = std::process::Command::new("secret-tool").arg("clear").args(Self::attrs(key)).output();
        self.fallback.delete(key)
    }

    fn backend(&self) -> &'static str {
        if std::process::Command::new("secret-tool").arg("--version").output().is_ok() {
            "Secret Service, or an owner only file if no keyring is running"
        } else {
            "owner only file"
        }
    }
}

#[cfg(not(windows))]
pub fn platform_store(paths: &Paths) -> Box<dyn SecretStore> {
    Box::new(SecretToolStore { fallback: FileStore::new(paths.config_dir.join("secrets")) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise(store: &dyn SecretStore, key: &str) {
        store.delete(key).unwrap();
        assert!(store.get(key).unwrap().is_none());
        store.set(key, &Secret::new("first")).unwrap();
        store.set(key, &Secret::new("second")).unwrap();
        assert_eq!(store.get(key).unwrap().unwrap().expose(), "second");
        store.delete(key).unwrap();
        assert!(store.get(key).unwrap().is_none());
        store.delete(key).unwrap();
    }

    #[test]
    fn memory_store() {
        exercise(&MemoryStore::default(), "k");
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("tk-mode-{}", crate::util::random_hex(6)));
        let store = FileStore::new(dir.clone());
        store.set("k", &Secret::new("v")).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join("k")), 0o600);
        assert_eq!(mode(&dir), 0o700);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn file_store() {
        let dir = std::env::temp_dir().join(format!("tk-secret-{}", crate::util::random_hex(6)));
        exercise(&FileStore::new(dir.clone()), "a/b");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(windows)]
    #[test]
    fn windows_credential_manager() {
        exercise(&WinCredStore, &format!("tunnelkeeper-test/{}", crate::util::random_hex(6)));
    }
}

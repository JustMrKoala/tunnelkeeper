//! The run journal. Intent is written before each change and the outcome
//! after it, so a crash at any point still leaves an honest record of what
//! may exist. Secrets never go in here.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::cloudflare::DnsRecord;
use crate::error::{Error, Result};
use crate::setup::SetupRequest;
use crate::util::{compact_timestamp, now_unix, random_hex, write_atomic};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Resource {
    Tunnel { account_id: String, tunnel_id: Option<String>, name: String },
    Ingress { account_id: String, tunnel_id: String, hostname: String, previous: Option<String> },
    DnsRecord { zone_id: String, record_id: Option<String>, hostname: String },
    /// An existing record removed with the user's approval, kept for rollback.
    DnsRemoved { zone_id: String, record: DnsRecord },
    Service { tunnel: String },
}

impl Resource {
    pub fn describe(&self) -> String {
        match self {
            Resource::Tunnel { name, tunnel_id, .. } => match tunnel_id {
                Some(id) => format!("tunnel {name} ({id})"),
                None => format!("tunnel {name}"),
            },
            Resource::Ingress { hostname, previous: None, .. } => format!("ingress rule for {hostname}"),
            Resource::Ingress { hostname, previous: Some(p), .. } => format!("ingress rule for {hostname} (was {p})"),
            Resource::DnsRecord { hostname, .. } => format!("DNS record for {hostname}"),
            Resource::DnsRemoved { record, .. } => format!("removal of DNS record {} {} {}", record.record_type, record.name, record.content),
            Resource::Service { tunnel } => format!("service for tunnel {tunnel}"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    /// Written before the change. Seen after a crash, the outcome is unknown.
    Intent,
    Done,
    /// The call failed. A lost reply means it may still have taken effect.
    Failed,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Entry {
    pub step: String,
    pub resource: Resource,
    pub state: EntryState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Failed,
    Complete,
    RolledBack,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Journal {
    pub id: String,
    pub started_at: i64,
    pub request: SetupRequest,
    pub status: RunStatus,
    pub step: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub entries: Vec<Entry>,
    #[serde(skip)]
    dir: PathBuf,
}

/// A run as plain data for display.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct RunView {
    pub id: String,
    pub tunnel: String,
    pub status: RunStatus,
    pub step: String,
    pub error: Option<String>,
    pub created: Vec<String>,
    pub unknown: Vec<String>,
}

impl Journal {
    pub fn view(&self) -> RunView {
        RunView {
            id: self.id.clone(),
            tunnel: self.request.tunnel.clone(),
            status: self.status,
            step: self.step.clone(),
            error: self.error.clone(),
            created: self.created().iter().map(|e| e.resource.describe()).collect(),
            unknown: self.unknown().iter().map(|e| e.resource.describe()).collect(),
        }
    }

    pub fn start(dir: &Path, request: SetupRequest) -> Result<Self> {
        let now = now_unix();
        let j = Journal {
            id: format!("{}-{}", compact_timestamp(now), random_hex(2)),
            started_at: now,
            request,
            status: RunStatus::Running,
            step: "start".into(),
            error: None,
            entries: vec![],
            dir: dir.to_path_buf(),
        };
        j.save()?;
        Ok(j)
    }

    fn file(dir: &Path, id: &str) -> PathBuf {
        dir.join(format!("{id}.json"))
    }

    pub fn load(dir: &Path, id: &str) -> Result<Self> {
        let valid = !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !valid {
            return Err(Error::Invalid(format!("invalid run ID {id:?}")));
        }
        let path = Self::file(dir, id);
        let text = std::fs::read_to_string(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::NotFound(format!("run {id}"))
            } else {
                Error::io(format!("read {}", path.display()), e)
            }
        })?;
        let mut j: Journal = serde_json::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        j.dir = dir.to_path_buf();
        Ok(j)
    }

    pub fn list(dir: &Path) -> Result<Vec<Journal>> {
        let mut runs = Vec::new();
        let read = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(runs),
            Err(e) => return Err(Error::io("read run folder", e)),
        };
        for item in read.flatten() {
            let name = item.file_name().to_string_lossy().to_string();
            if let Some(id) = name.strip_suffix(".json") {
                runs.push(Self::load(dir, id)?);
            }
        }
        runs.sort_by(|a, b| b.id.cmp(&a.id));
        Ok(runs)
    }

    pub fn save(&self) -> Result<()> {
        let text = serde_json::to_vec_pretty(self).map_err(|e| Error::Config(e.to_string()))?;
        write_atomic(&Self::file(&self.dir, &self.id), &text)
    }

    /// Records intent and returns the entry index.
    pub fn intent(&mut self, resource: Resource) -> Result<usize> {
        self.entries.push(Entry { step: self.step.clone(), resource, state: EntryState::Intent, error: None });
        self.save()?;
        Ok(self.entries.len() - 1)
    }

    pub fn done(&mut self, index: usize, resource: Resource) -> Result<()> {
        let e = &mut self.entries[index];
        e.resource = resource;
        e.state = EntryState::Done;
        e.error = None;
        self.save()
    }

    pub fn failed(&mut self, index: usize, error: &Error) -> Result<()> {
        let e = &mut self.entries[index];
        e.state = EntryState::Failed;
        e.error = Some(error.to_string());
        self.save()
    }

    /// A later attempt found that an unknown outcome did take effect. The
    /// resource is then ours, so rollback must cover it.
    pub fn claim_unknown(&mut self, matches: impl Fn(&Resource) -> bool, resource: Resource) -> Result<bool> {
        let found = self.entries.iter_mut().find(|e| e.state != EntryState::Done && matches(&e.resource));
        match found {
            Some(e) => {
                e.resource = resource;
                e.state = EntryState::Done;
                e.error = None;
                self.save()?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// A later attempt found nothing, so the earlier try had no effect.
    pub fn drop_unknown(&mut self, matches: impl Fn(&Resource) -> bool) -> Result<()> {
        self.entries.retain(|e| e.state == EntryState::Done || !matches(&e.resource));
        self.save()
    }

    pub fn created(&self) -> Vec<&Entry> {
        self.entries.iter().filter(|e| e.state == EntryState::Done).collect()
    }

    pub fn unknown(&self) -> Vec<&Entry> {
        self.entries.iter().filter(|e| e.state != EntryState::Done).collect()
    }

    pub fn remove_file(&self) {
        let _ = std::fs::remove_file(Self::file(&self.dir, &self.id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SetupRequest {
        SetupRequest { tunnel: "web".into(), routes: vec![], install_service: false, zone: None, replace_dns: vec![] }
    }

    fn tunnel(id: Option<&str>) -> Resource {
        Resource::Tunnel { account_id: "a".into(), tunnel_id: id.map(str::to_string), name: "web".into() }
    }

    fn temp() -> PathBuf {
        std::env::temp_dir().join(format!("tk-journal-{}", random_hex(6)))
    }

    #[test]
    fn intent_survives_on_disk_before_the_outcome() {
        let dir = temp();
        let mut j = Journal::start(&dir, request()).unwrap();
        j.intent(tunnel(None)).unwrap();
        let loaded = Journal::load(&dir, &j.id).unwrap();
        assert_eq!(loaded.entries[0].state, EntryState::Intent);
        assert_eq!(loaded.unknown().len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn claim_turns_unknown_into_created() {
        let dir = temp();
        let mut j = Journal::start(&dir, request()).unwrap();
        let i = j.intent(tunnel(None)).unwrap();
        j.failed(i, &Error::Network("lost".into())).unwrap();
        let claimed = j.claim_unknown(|r| matches!(r, Resource::Tunnel { .. }), tunnel(Some("id"))).unwrap();
        assert!(claimed);
        assert_eq!(j.created().len(), 1);
        assert!(j.unknown().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn run_ids_cannot_escape_the_folder() {
        assert!(Journal::load(Path::new("."), "../secret").is_err());
    }

    #[test]
    fn newest_run_is_listed_first() {
        let dir = temp();
        let a = Journal::start(&dir, request()).unwrap();
        let mut b = a.clone();
        b.id = format!("9{}", a.id);
        b.save().unwrap();
        let runs = Journal::list(&dir).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].id, b.id);
        assert_eq!(runs[1].id, a.id);
        let _ = std::fs::remove_dir_all(dir);
    }
}

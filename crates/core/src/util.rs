//! Small helpers kept here to avoid extra dependencies.

use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("OS random source failed");
    hex(&buf)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A random RFC 4122 version 4 UUID.
pub fn random_uuid() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("OS random source failed");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut f = std::fs::File::open(path).map_err(|e| Error::io(format!("open {}", path.display()), e))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| Error::io(format!("read {}", path.display()), e))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

/// Writes through a temp file and rename, so readers never see a partial file.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| Error::io(format!("create {}", dir.display()), e))?;
    }
    let tmp = path.with_extension(format!("tmp{}", random_hex(4)));
    std::fs::write(&tmp, data).map_err(|e| Error::io(format!("write {}", tmp.display()), e))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Error::io(format!("replace {}", path.display()), e)
    })
}

/// Like `write_atomic`, but the data is never readable by others, not even
/// briefly. On Windows the protection comes from the folder ACL.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| Error::io(format!("create {}", dir.display()), e))?;
    }
    let tmp = path.with_extension(format!("tmp{}", random_hex(4)));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).map_err(|e| Error::io(format!("create {}", tmp.display()), e))?;
    f.write_all(data).map_err(|e| Error::io(format!("write {}", tmp.display()), e))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Error::io(format!("replace {}", path.display()), e)
    })
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `20261105-154453` in UTC, used in run IDs.
pub fn compact_timestamp(unix: i64) -> String {
    let (y, m, d) = civil_from_days(unix.div_euclid(86_400));
    let s = unix.rem_euclid(86_400);
    format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}", s / 3600, s % 3600 / 60, s % 60)
}

/// Parses an HTTP date such as `Thu, 05 Nov 2026 15:44:53 GMT`.
pub fn parse_http_date(s: &str) -> Option<i64> {
    let p: Vec<&str> = s.split_whitespace().collect();
    if p.len() != 6 {
        return None;
    }
    let day: u32 = p[1].parse().ok()?;
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        .iter()
        .position(|m| *m == p[2])? as u32
        + 1;
    let year: i64 = p[3].parse().ok()?;
    let t: Vec<i64> = p[4].split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
    if t.len() != 3 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + t[0] * 3600 + t[1] * 60 + t[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip() {
        let unix = parse_http_date("Thu, 05 Nov 2026 15:44:53 GMT").unwrap();
        assert_eq!(compact_timestamp(unix), "20261105-154453");
    }

    #[test]
    fn bad_dates_are_none() {
        assert_eq!(parse_http_date("yesterday"), None);
    }

    #[test]
    fn uuid_shape() {
        let u = random_uuid();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
    }
}

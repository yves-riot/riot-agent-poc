//! Durable outbox for sensitive-data reports: one JSON file per report, written atomically,
//! deleted once parrot accepted it. Reports carry counts only (never values), so the spool holds
//! nothing sensitive. A report re-sent with the same `session_id` overwrites its file: the
//! endpoint upserts, so an override ("pasted the original") replaces the redacted report.

use std::path::{Path, PathBuf};

use riot_api::SensitiveDataReport;

pub struct Spool {
    dir: PathBuf,
}

impl Spool {
    pub fn new(data_dir: &Path) -> std::io::Result<Self> {
        let dir = data_dir.join("outbox");
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn push(&self, report: &SensitiveDataReport) -> std::io::Result<()> {
        let path = self.dir.join(format!("{}.json", report.session_id));
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(report)?)?;
        std::fs::rename(tmp, path)
    }

    pub fn pending(&self) -> Vec<(PathBuf, SensitiveDataReport)> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return vec![] };
        let mut out: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .filter_map(|p| Some((p.clone(), serde_json::from_slice(&std::fs::read(&p).ok()?).ok()?)))
            .collect();
        out.sort_by_key(|(_, r): &(PathBuf, SensitiveDataReport)| r.occurred_at);
        out
    }

    pub fn len(&self) -> usize {
        std::fs::read_dir(&self.dir).map(|d| d.filter_map(Result::ok).count()).unwrap_or(0)
    }

    pub fn done(&self, path: &Path) {
        let _ = std::fs::remove_file(path);
    }
}

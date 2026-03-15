use kage_types::audit::AuditEvent;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn default_path() -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            dirs::home_dir().map(|h| {
                h.join("Library")
                    .join("Application Support")
                    .join("kage")
                    .join("audit.ndjson")
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            dirs::home_dir().map(|h| h.join(".kage").join("v3").join("audit.ndjson"))
        }
    }

    pub fn open_default() -> Option<Self> {
        Self::default_path().map(Self::new)
    }

    pub fn append(&self, event: &AuditEvent) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut line =
            serde_json::to_vec(event).map_err(io::Error::other)?;
        line.push(b'\n');
        file.write_all(&line)
    }

    pub fn append_or_log(&self, event: &AuditEvent) {
        if let Err(e) = self.append(event) {
            eprintln!("audit: failed to write event: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kage_types::adapter::AdapterId;
    use kage_types::audit::{AuditOutcome, AUDIT_SCHEMA_VERSION};
    use kage_types::capability::Capability;
    use kage_types::scope::AuthoritativeScope;

    #[test]
    fn append_creates_file_and_writes_ndjson() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir").join("audit.ndjson");
        let log = AuditLog::new(path.clone());

        let event = AuditEvent {
            schema_version: AUDIT_SCHEMA_VERSION,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            session_id: None,
            adapter: AdapterId::new(AdapterId::AGE),
            capability: Capability::WrapUnwrap,
            operation: "wrap".to_string(),
            scope: AuthoritativeScope {
                org: Some("acme".to_string()),
                env: Some("dev".to_string()),
                kid_bech32: None,
            },
            outcome: AuditOutcome::Success,
            platform: Some("linux".to_string()),
            advisory: None,
            error: None,
            duration_seconds: None,
            metadata: None,
        };

        log.append(&event).unwrap();
        log.append(&event).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(parsed["schema_version"], 2);
            assert_eq!(parsed["adapter"], "age");
            assert_eq!(parsed["capability"], "wrap_unwrap");
            assert_eq!(parsed["operation"], "wrap");
            assert_eq!(parsed["outcome"], "success");
        }
    }
}

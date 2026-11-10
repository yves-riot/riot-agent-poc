//! The extension's conformance corpus (`sonar-detection/conformance`), run inside this crate's
//! QuickJS engine. Same cases, same runner, same assertions as the extension's vitest suite.

use std::path::PathBuf;
use std::time::Duration;

use riot_detect::{Engine, EngineConfig};
use serde::Deserialize;

#[derive(Deserialize)]
struct Report {
    file: String,
    verdicts: Vec<Verdict>,
}

#[derive(Deserialize)]
struct Verdict {
    id: String,
    skipped: Option<String>,
    failures: Vec<String>,
}

fn dist() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../js/dist")
}

#[test]
fn extension_conformance_corpus_passes_on_quickjs() {
    let fixtures = PathBuf::from(std::fs::read_to_string(dist().join("conformance-dir.txt")).unwrap().trim());
    let runner = std::fs::read_to_string(dist().join("conformance.js")).unwrap();
    let engine = Engine::start(EngineConfig::default()).unwrap();

    let json = engine
        .eval_and_call(runner, fixtures, "SonarConformance.runAll(true)".into(), Duration::from_secs(120))
        .unwrap();
    let reports: Vec<Report> = serde_json::from_str(&json).unwrap();

    let (mut passed, mut skipped, mut failed) = (0, 0, Vec::new());
    for report in &reports {
        for v in &report.verdicts {
            if v.skipped.is_some() {
                skipped += 1;
            } else if v.failures.is_empty() {
                passed += 1;
            } else {
                failed.push(format!("{} > {}: {}", report.file, v.id, v.failures.join(" | ")));
            }
        }
    }
    eprintln!("conformance: {passed} passed, {skipped} skipped, {} failed", failed.len());
    assert!(failed.is_empty(), "conformance failures:\n{}", failed.join("\n"));
    assert!(passed > 200, "corpus unexpectedly small: {passed}");
}

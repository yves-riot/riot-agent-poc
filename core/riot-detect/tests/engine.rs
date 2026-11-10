use std::collections::BTreeMap;
use std::time::Instant;

use riot_detect::{Engine, EngineConfig, Error, FileScan, Options};

fn engine() -> Engine {
    Engine::start(EngineConfig::default()).unwrap()
}

#[test]
fn redacts_with_numbered_tokens_and_reuses_them_within_a_scope() {
    let e = engine();
    let first = e
        .redact("IBAN FR76 3000 6000 0112 3456 7890 189 / jean.dupont@acme.fr", "com.openai.chat", &Options::default())
        .unwrap();
    assert_eq!(first.text, "IBAN [IBAN_1] / [EMAIL_1]");
    assert_eq!(first.findings.len(), 2);
    assert!(first.findings.iter().all(|f| !f.token.is_empty()));

    // Same value later in the same app: same token. A new value: the next number.
    let second = e
        .redact("encore jean.dupont@acme.fr et marie@acme.fr", "com.openai.chat", &Options::default())
        .unwrap();
    assert_eq!(second.text, "encore [EMAIL_1] et [EMAIL_2]");

    // Another app is another conversation: numbering restarts.
    let other = e.redact("marie@acme.fr", "com.anthropic.claudefordesktop", &Options::default()).unwrap();
    assert_eq!(other.text, "[EMAIL_1]");
}

#[test]
fn detokenizes_known_tokens_only() {
    let e = engine();
    e.redact("mail jean.dupont@acme.fr", "app", &Options::default()).unwrap();
    let back = e.detokenize("Réponse pour [EMAIL_1] et [EMAIL_7]", "app").unwrap();
    assert_eq!(back.text, "Réponse pour jean.dupont@acme.fr et [EMAIL_7]");
    assert_eq!(back.replaced, 1);
    // Unknown scope: untouched.
    assert_eq!(e.detokenize("[EMAIL_1]", "other").unwrap().replaced, 0);
}

#[test]
fn honours_disabled_categories() {
    let e = engine();
    let options = Options { categories: Some(BTreeMap::from([("personal_data".to_owned(), false)])), max_bytes: None };
    let out = e.detect("mail jean.dupont@acme.fr key AKIAIOSFODNN7EXAMPLE", &options).unwrap();
    let flags: Vec<_> = out.detections.iter().map(|d| d.flag.as_str()).collect();
    assert_eq!(flags, ["api_key"]);
}

#[test]
fn scans_files_and_fails_closed() {
    let e = engine();
    let o = Options::default();
    let hit = e.scan_bytes("notes.txt", "", b"key AKIAIOSFODNN7EXAMPLE".to_vec(), &o, None).unwrap();
    assert!(matches!(&hit, FileScan::Scanned { detections, .. } if detections[0].flag == "api_key"));
    assert!(!hit.is_clean());

    assert!(e.scan_bytes("notes.txt", "", b"rien".to_vec(), &o, None).unwrap().is_clean());
    // Invalid UTF-8 must not scan clean.
    let bad = e.scan_bytes("notes.txt", "", vec![0xff, 0xfe, 0x00], &o, None).unwrap();
    assert!(matches!(bad, FileScan::Error { .. }), "{bad:?}");
    // Garbage pdf: error, not clean.
    let pdf = e.scan_bytes("a.pdf", "application/pdf", b"%PDF-1.4 garbage".to_vec(), &o, None).unwrap();
    assert!(matches!(pdf, FileScan::Error { .. }), "{pdf:?}");
    assert!(matches!(e.scan_bytes("a.png", "image/png", vec![1, 2], &o, None).unwrap(), FileScan::Unsupported { .. }));
    assert!(e.is_supported("x.docx").unwrap());
    assert!(!e.is_supported("x.png").unwrap());
}

#[test]
fn deadline_interrupts_a_scan_and_the_engine_keeps_working() {
    let e = engine();
    let big = "Jean Dupont habite à Paris. ".repeat(30_000).into_bytes(); // ~840 KB of text
    let started = Instant::now();
    let r = e.scan_bytes("big.txt", "", big, &Options::default(), Some(Instant::now()));
    assert!(matches!(r, Err(Error::Timeout)), "{r:?}");
    assert!(started.elapsed().as_millis() < 500, "interrupt took {:?}", started.elapsed());
    // Still usable afterwards.
    assert_eq!(e.redact("a@b.fr", "s", &Options::default()).unwrap().text, "[EMAIL_1]");
}

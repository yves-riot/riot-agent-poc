//! Latency and memory of the embedded engine: `cargo run -p riot-detect --release --example bench`.
use std::time::{Duration, Instant};

use riot_detect::{Engine, EngineConfig, Options};

const PROSE: &str = "Bonjour l'équipe, suite à notre échange avec Jean Dupont hier, je vous transmets le récapitulatif \
du dossier. Le client souhaite revoir les conditions du contrat avant la fin du trimestre et nous demande une \
proposition chiffrée. Merci de me faire un retour rapide. ";
const PII: &[&str] = &[
    "Contact : marie.durand@acme-corp.fr. ",
    "IBAN FR76 3000 6000 0112 3456 7890 189. ",
    "Tél. +33 6 12 34 56 78. ",
    "clé AKIAIOSFODNN7EXAMPLE. ",
];

fn text_of(bytes: usize) -> String {
    let mut s = String::new();
    let mut i = 0;
    while s.len() < bytes {
        s.push_str(PROSE);
        if i % 3 == 0 {
            s.push_str(PII[(i / 3) % PII.len()]);
        }
        i += 1;
    }
    s.truncate(s.floor_char_boundary(bytes));
    s
}

fn rss_mib() -> f64 {
    let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().parse::<f64>().unwrap_or(0.0) / 1024.0
}

fn percentiles(mut v: Vec<Duration>) -> String {
    v.sort();
    let p = |q: f64| v[((v.len() as f64 - 1.0) * q).round() as usize].as_secs_f64() * 1000.0;
    format!("p50 {:>7.1} ms  p95 {:>7.1} ms  max {:>7.1} ms", p(0.5), p(0.95), p(1.0))
}

fn main() {
    let rss0 = rss_mib();
    let t = Instant::now();
    let engine = Engine::start(EngineConfig::default()).unwrap();
    println!("start + warm-up: {:.0} ms, RSS {:.1} → {:.1} MiB", t.elapsed().as_secs_f64() * 1000.0, rss0, rss_mib());

    let o = Options::default();
    for (label, size, runs) in [("paste 1 KB", 1_000, 50), ("paste 10 KB", 10_000, 30), ("paste 64 KB", 64_000, 10)] {
        let text = text_of(size);
        let mut times = vec![];
        let mut n = 0;
        for _ in 0..runs {
            let t = Instant::now();
            n = engine.redact(&text, "bench", &o).unwrap().detections.len();
            times.push(t.elapsed());
        }
        println!("{label:<14} {}  ({n} detections)", percentiles(times));
    }

    for (label, size) in [("file txt 256 KB", 256_000), ("file txt 1 MiB", 1_040_000)] {
        let bytes = text_of(size).into_bytes();
        let mut times = vec![];
        let mut n = 0;
        for _ in 0..3 {
            let t = Instant::now();
            if let riot_detect::FileScan::Scanned { detections, .. } =
                engine.scan_bytes("big.txt", "", bytes.clone(), &o, None).unwrap()
            {
                n = detections.len();
            }
            times.push(t.elapsed());
        }
        println!("{label:<14} {}  ({n} detections)", percentiles(times));
    }

    let heap = engine.heap_stats().unwrap();
    println!(
        "QuickJS heap: {:.1} MiB malloc, process RSS {:.1} MiB",
        heap.malloc_size as f64 / 1048576.0,
        rss_mib()
    );
}

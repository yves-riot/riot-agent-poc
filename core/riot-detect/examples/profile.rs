//! Per-detector cost inside QuickJS: `cargo run -p riot-detect --release --example profile [bytes]`.
use std::time::Duration;

use riot_detect::{Engine, EngineConfig};

const SCRIPT: &str = r#"
globalThis.profileDetectors = async (n) => {
  const PROSE = "Bonjour l'équipe, suite à notre échange avec Jean Dupont hier, je vous transmets le récapitulatif du dossier. Le client souhaite revoir les conditions du contrat avant la fin du trimestre et nous demande une proposition chiffrée. Merci de me faire un retour rapide. ";
  const PII = ["Contact : marie.durand@acme-corp.fr. ", "IBAN FR76 3000 6000 0112 3456 7890 189. ", "Tél. +33 6 12 34 56 78. ", "clé AKIAIOSFODNN7EXAMPLE. "];
  let text = '', i = 0;
  while (text.length < n) { text += PROSE; if (i % 3 === 0) text += PII[(i / 3 | 0) % 4]; i++; }
  text = text.slice(0, n);
  const rows = [];
  for (const d of Sonar.engine.DETECTORS) {
    const t = performance.now();
    const hits = await d.detect(text, { claimed: [] });
    rows.push([d.id, performance.now() - t, hits.length]);
  }
  rows.sort((a, b) => b[1] - a[1]);
  const total = rows.reduce((s, r) => s + r[1], 0);
  return JSON.stringify({ total, top: rows.slice(0, 12) });
};
"#;

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(256_000);
    let engine = Engine::start(EngineConfig::default()).unwrap();
    let out = engine
        .eval_and_call(SCRIPT.into(), std::env::temp_dir(), format!("profileDetectors({n})"), Duration::from_secs(600))
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    println!("{n} bytes, all detectors: {:.0} ms", v["total"].as_f64().unwrap());
    for row in v["top"].as_array().unwrap() {
        println!("  {:<28} {:>9.1} ms  {} hits", row[0].as_str().unwrap(), row[1].as_f64().unwrap(), row[2]);
    }
}

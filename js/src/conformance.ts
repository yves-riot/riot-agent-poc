/**
 * The extension's conformance corpus, run against the engine loaded in the same QuickJS
 * context (`globalThis.Sonar.engine`). Case files are inlined at build time by build.mjs
 * (`virtual:conformance-cases`); fixtures are read by the Rust host.
 */
import { loadCaseFile, runCase, type ConformanceCase, type Engine, type Verdict } from '@sonar-conformance/runner';
import caseFiles from 'virtual:conformance-cases';

declare const __riotConformance: { readFixture(path: string): Uint8Array };

type Report = { file: string; verdicts: Verdict[] };

async function runAll(nlp: boolean): Promise<string> {
  const engine = (globalThis as unknown as { Sonar: { engine: Engine } }).Sonar.engine;
  const readFixture = async (path: string) => __riotConformance.readFixture(path);
  const reports: Report[] = [];
  for (const [file, json] of caseFiles as [string, unknown][]) {
    const cases: ConformanceCase[] = loadCaseFile(json, file);
    const verdicts: Verdict[] = [];
    for (const c of cases) {
      try {
        verdicts.push(await runCase(c, engine, { readFixture, nlp }));
      } catch (e) {
        verdicts.push({ id: c.id, failures: [`threw: ${e instanceof Error ? e.message : String(e)}`] });
      }
    }
    reports.push({ file, verdicts });
  }
  return JSON.stringify(reports);
}

(globalThis as Record<string, unknown>).SonarConformance = { runAll };

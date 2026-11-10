/**
 * Entry point evaluated by the Rust host (riot-detect). Wires the engine's host seams, then
 * exposes `globalThis.Sonar`: the raw engine (for the conformance runner) and `Sonar.host`, a
 * JSON-in / JSON-out surface so the Rust side only ever passes strings and byte arrays.
 */
import { BrowserLikeXmlParser } from './polyfills';
import * as engine from '@tryriot/sonar-detection';
import { mint, record, valueFor, detectionCounts } from '@tryriot/sonar-guard-core';

const describe = (v: unknown): string => {
  if (v instanceof Error) return `${v.name}: ${v.message}${v.stack ? `\n${v.stack}` : ''}`;
  if (typeof v === 'object' && v !== null) {
    try {
      return JSON.stringify(v, (_k, x: unknown) => (x instanceof Error ? describe(x) : x));
    } catch {
      return String(v);
    }
  }
  return String(v);
};
engine.setLogger({
  warn: (...args: unknown[]) => __riot.log('warn', args.map(describe).join(' ')),
  error: (...args: unknown[]) => __riot.log('error', args.map(describe).join(' ')),
});
engine.setXmlParser(new BrowserLikeXmlParser());
// Native extraction returns the same segments pdf-text.ts collects (page text, annotation
// contents, form-field values); the joining and the ceiling / zero-text rules stay here, as there.
const PDF_MAX_TEXT_BYTES = 1_048_576;
engine.setPdfExtractor(async (file) => {
  const segments = JSON.parse(__riot.pdfText(new Uint8Array(await file.arrayBuffer()))) as string[];
  let budget = 0;
  const encoder = new TextEncoder();
  for (const s of segments) {
    budget += encoder.encode(s).byteLength;
    if (budget > PDF_MAX_TEXT_BYTES) throw new Error('pdf text exceeds the scan ceiling');
  }
  if (!segments.some((s) => /\S/.test(s))) throw new Error('pdf contains no extractable text');
  const boundaries: number[] = [];
  let text = '';
  segments.forEach((part, i) => {
    if (i > 0) {
      boundaries.push(text.length);
      text += '\n';
    }
    text += part;
  });
  return { text, boundaries };
});

type Categories = Partial<Record<engine.CategoryId, boolean>>;
type Options = { categories?: Categories; maxBytes?: number };

const view = (d: engine.Detection) => ({
  flag: d.flag,
  category: d.category,
  severity: d.severity,
  name: d.name,
  label: d.label,
  value: d.value,
  index: d.index,
});

/** Detect and replace with numbered, reversible tokens remembered under `scope`, the native
 *  equivalent of a chat conversation (e.g. `com.openai.chat`). The value/token map lives in this
 *  JS heap only: never persisted, never returned except to the process that asked for it. */
async function redactInScope(text: string, scope: string, optionsJson: string): Promise<string> {
  const options = JSON.parse(optionsJson) as Options;
  const result = await engine.redact(text, options);
  const tokenized = mint(scope, result.detections, text, '');
  record(scope, tokenized.findings);
  return JSON.stringify({
    text: tokenized.text,
    oversized: result.oversized,
    detections: result.detections.map(view),
    findings: tokenized.findings.map(({ flag, label, name, token }) => ({ flag, label, name, token })),
    counts: detectionCounts(result.detections),
  });
}

/** Swap every known token of `scope` back to its value (copy-out of the AI app). */
function detokenize(text: string, scope: string): string {
  let replaced = 0;
  const out = text.replace(engine.anyTokenScanRegex(), (token) => {
    const value = valueFor(scope, token);
    if (value === undefined) return token;
    replaced++;
    return value;
  });
  return JSON.stringify({ text: out, replaced });
}

async function detect(text: string, optionsJson: string): Promise<string> {
  const result = await engine.detect(text, JSON.parse(optionsJson) as Options);
  return JSON.stringify({
    detections: result.detections.map(view),
    oversized: result.oversized,
    failed: result.failed,
    counts: detectionCounts(result.detections),
  });
}

async function scanFile(name: string, mime: string, bytes: Uint8Array, optionsJson: string): Promise<string> {
  const result = await engine.scanFile(engine.fileLike(name, mime, bytes), JSON.parse(optionsJson) as Options);
  if (result.status === 'scanned') {
    return JSON.stringify({
      status: 'scanned',
      format: result.format,
      detections: result.detections.map(view),
      counts: detectionCounts(result.detections),
    });
  }
  if (result.status === 'error') {
    const error = result.error instanceof Error ? result.error.message : String(result.error);
    return JSON.stringify({ status: 'error', stage: result.stage, error });
  }
  return JSON.stringify(result);
}

const supportedFileFormat = (name: string, mime: string): boolean =>
  engine.isSupportedFileFormat(engine.fileLike(name, mime, new Uint8Array(0)));

(globalThis as Record<string, unknown>).Sonar = {
  engine,
  host: { redactInScope, detokenize, detect, scanFile, supportedFileFormat },
};

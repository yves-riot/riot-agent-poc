/**
 * The web globals @tryriot/sonar-detection reads, for QuickJS (which has none of them).
 * Must be imported before the engine. Each one is installed only when missing, so the same
 * bundle also runs under Node for debugging.
 *
 * `__riot` is installed by the Rust host (riot-detect) before this bundle is evaluated.
 */
import { DOMParser as XmlDomParser, Node as XmlNode } from '@xmldom/xmldom';

declare global {
  // eslint-disable-next-line no-var
  var __riot: {
    /** Strict (fatal) or lossy UTF-8 decoding, done natively. Throws on invalid bytes when fatal. */
    utf8Decode(bytes: Uint8Array, fatal: boolean): string;
    /** Milliseconds from a monotonic clock. */
    nowMs(): number;
    log(level: 'warn' | 'error', message: string): void;
    /** pdf text extraction, done natively; returns a JSON array of text segments or throws. */
    pdfText(bytes: Uint8Array): string;
  };
}

const g = globalThis as Record<string, unknown>;

// --- TextEncoder: pure JS (lone surrogates become U+FFFD, like the web's). ---
class Utf8Encoder {
  readonly encoding = 'utf-8';
  encode(input = ''): Uint8Array {
    const out: number[] = [];
    for (let i = 0; i < input.length; i++) {
      let c = input.charCodeAt(i);
      if (c >= 0xd800 && c <= 0xdbff && i + 1 < input.length) {
        const d = input.charCodeAt(i + 1);
        if (d >= 0xdc00 && d <= 0xdfff) {
          c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
          i++;
        } else c = 0xfffd;
      } else if (c >= 0xd800 && c <= 0xdfff) c = 0xfffd;

      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return new Uint8Array(out);
  }
}

// --- TextDecoder: UTF-8 only, delegated to Rust (fast, and `fatal` is exact). ---
class Utf8Decoder {
  readonly encoding = 'utf-8';
  readonly fatal: boolean;
  constructor(label = 'utf-8', options: { fatal?: boolean } = {}) {
    if (!/^utf-?8$/i.test(label)) throw new RangeError(`unsupported encoding ${label}`);
    this.fatal = options.fatal === true;
  }
  decode(input?: ArrayBuffer | ArrayBufferView): string {
    if (input === undefined) return '';
    const bytes =
      input instanceof Uint8Array
        ? input
        : ArrayBuffer.isView(input)
          ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
          : new Uint8Array(input);
    return __riot.utf8Decode(bytes, this.fatal);
  }
}

// compromise reads the global object as `self`.
if (typeof g.self === 'undefined') g.self = globalThis;
if (typeof g.TextEncoder === 'undefined') g.TextEncoder = Utf8Encoder;
if (typeof g.TextDecoder === 'undefined') g.TextDecoder = Utf8Decoder;
if (typeof g.performance === 'undefined') g.performance = { now: () => __riot.nowMs() };

// --- DOMParser for the OOXML extractors: xmldom, shaped like the browser's. ---

// docx.ts reads `node.parentElement`, which xmldom does not implement.
if (!('parentElement' in XmlNode.prototype)) {
  Object.defineProperty(XmlNode.prototype, 'parentElement', {
    get(this: { parentNode: { nodeType: number } | null }) {
      const p = this.parentNode;
      return p && p.nodeType === 1 ? p : null;
    },
  });
}

const PARSER_ERROR = '<parsererror xmlns="http://www.mozilla.org/newlayout/xml/parsererror.xml"/>';

/** Browsers never throw on malformed XML: they return a document holding a `<parsererror>`,
 *  which ooxml.ts checks for. xmldom reports through `onError` instead, so any error or fatal
 *  error is turned into that same document. */
export class BrowserLikeXmlParser {
  parseFromString(xml: string, type: string): Document {
    try {
      const strict = new XmlDomParser({
        onError: (level: string, message: string) => {
          if (level !== 'warning') throw new Error(message);
        },
      });
      return strict.parseFromString(xml, type as 'application/xml') as unknown as Document;
    } catch {
      return new XmlDomParser().parseFromString(PARSER_ERROR, 'application/xml') as unknown as Document;
    }
  }
}

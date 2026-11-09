// Strict, bounded JSON for untrusted developer evidence, mirroring the companion's
// parse_json() limits: duplicate keys, excessive depth/size and non-finite numbers are
// rejected. Nothing in a payload is ever interpreted or executed.
// canonical() is byte-compatible with Python json.dumps(sort_keys=True, ensure_ascii=True,
// separators=(',', ':')) + "\n", which the companion uses for bundle hashing.

export const MAX_BYTES = 5 * 1024 * 1024;

export class JsonRejected extends Error {}

type J = null | boolean | number | string | J[] | { [k: string]: J };

export function parseStrict(text: string): J {
  let i = 0;
  let nodes = 0;
  const fail = (m: string): never => {
    throw new JsonRejected(m);
  };
  const ws = () => {
    while (i < text.length && (text[i] === " " || text[i] === "\n" || text[i] === "\r" || text[i] === "\t")) i++;
  };
  const value = (depth: number): J => {
    if (depth > 48) fail("JSON nesting too deep.");
    if (++nodes > 200_000) fail("JSON has too many nodes.");
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const o: { [k: string]: J } = Object.create(null);
      let n = 0;
      ws();
      if (text[i] === "}") {
        i++;
        return o;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("Expected object key.");
        const k = str();
        if (Object.prototype.hasOwnProperty.call(o, k)) fail("Duplicate JSON object key.");
        ws();
        if (text[i++] !== ":") fail("Expected ':'.");
        o[k] = value(depth + 1);
        if (++n > 30_000) fail("Too many object properties.");
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return o;
        }
        fail("Expected ',' or '}'.");
      }
    }
    if (c === "[") {
      i++;
      const a: J[] = [];
      ws();
      if (text[i] === "]") {
        i++;
        return a;
      }
      for (;;) {
        a.push(value(depth + 1));
        if (a.length > 20_000) fail("Too many array entries.");
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return a;
        }
        fail("Expected ',' or ']'.");
      }
    }
    if (c === '"') return str();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    const m = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i, i + 400));
    if (!m) fail("Invalid JSON value.");
    i += m![0].length;
    if (/^-?\d+$/.test(m![0])) {
      if (m![0].length > 128) fail("JSON integer exceeds limit.");
      const n = Number(m![0]);
      if (!Number.isSafeInteger(n)) fail("JSON integer outside the supported range.");
      return n;
    }
    const f = Number(m![0]);
    if (!Number.isFinite(f)) fail("Non-finite JSON number.");
    return f;
  };
  const str = (): string => {
    i++; // opening quote
    let out = "";
    for (;;) {
      if (i >= text.length) fail("Unterminated string.");
      const ch = text[i++];
      if (ch === '"') break;
      if (ch === "\\") {
        const e = text[i++];
        if (e === "u") {
          const h = text.slice(i, i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("Invalid unicode escape.");
          out += String.fromCharCode(parseInt(h, 16));
          i += 4;
        } else {
          const map: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
          if (!(e in map)) fail("Invalid escape.");
          out += map[e];
        }
      } else {
        if (ch.charCodeAt(0) < 0x20) fail("Control character in string.");
        out += ch;
      }
      if (out.length > 65_536) fail("JSON string exceeds limit.");
    }
    return out;
  };
  const v = value(0);
  ws();
  if (i !== text.length) fail("Trailing data after JSON.");
  return v;
}

export function decodeUtf8(bytes: Uint8Array): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new JsonRejected("Body is not valid UTF-8.");
  }
}

function escape(s: string): string {
  let o = '"';
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if (c === 0x22) o += '\\"';
    else if (c === 0x5c) o += "\\\\";
    else if (c === 0x0a) o += "\\n";
    else if (c === 0x0d) o += "\\r";
    else if (c === 0x09) o += "\\t";
    else if (c === 0x08) o += "\\b";
    else if (c === 0x0c) o += "\\f";
    else if (c < 0x20 || c > 0x7e) o += c === 0x7f ? "\x7f" : "\\u" + c.toString(16).padStart(4, "0");
    else o += s[k];
  }
  return o + '"';
}

const byCodePoint = (a: string, b: string) => {
  const A = [...a];
  const B = [...b];
  for (let k = 0; k < Math.min(A.length, B.length); k++) {
    const d = (A[k].codePointAt(0) as number) - (B[k].codePointAt(0) as number);
    if (d) return d;
  }
  return A.length - B.length;
};

function ser(v: unknown): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new JsonRejected("Non-finite number.");
    if (Number.isInteger(v)) return String(v);
    const s = String(v);
    // Python repr differs from JS for exponent forms; refuse rather than mis-hash.
    if (/e/i.test(s)) throw new JsonRejected("Unsupported number form.");
    return s;
  }
  if (typeof v === "string") return escape(v);
  if (Array.isArray(v)) return "[" + v.map(ser).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v as object).sort(byCodePoint);
    return "{" + keys.map((k) => escape(k) + ":" + ser((v as Record<string, unknown>)[k])).join(",") + "}";
  }
  throw new JsonRejected("Unsupported value.");
}

export function canonical(v: unknown): string {
  return ser(v) + "\n";
}

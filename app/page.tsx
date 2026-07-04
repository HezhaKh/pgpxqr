"use client";

import { useCallback, useEffect, useRef, useState } from "react";

interface SubkeyInfo {
  keyId: string;
  fingerprint: string;
  algorithm: string;
  created: string;
}

interface KeyInfo {
  fingerprint: string;
  keyId: string;
  algorithm: string;
  created: string;
  expires: string;
  expired: boolean;
  revoked: boolean;
  userIds: string[];
  subkeys: SubkeyInfo[];
}

interface SignatureInfo {
  keyId: string;
  status: "valid" | "invalid" | "no-matching-key";
  matchedFingerprint?: string;
  created?: string;
  detail?: string;
  signerRevoked?: boolean;
  signerExpired?: boolean;
}

interface VerifyResult {
  ok: boolean;
  error?: string;
  errorKind?: string;
  email: string;
  keyserver?: string;
  keyserverNote?: string;
  keys?: KeyInfo[];
  signatures?: SignatureInfo[];
  anyValid?: boolean;
  anyInvalid?: boolean;
  validButUntrustedKey?: boolean;
  keyserverVerifiesOwnership?: boolean;
  warnings?: string[];
  signedText?: string;
}

// Pixel-art fingerprint seal, drawn on a 23x23 grid.
const SEAL_GRID = `
...........#...........
.........##.##.........
.......##.....##.......
.....##.........##.....
...##....#####....##...
..#....##.....#.....#..
..#...##............#..
..#..##..#####......#..
..#..#..##...##.....#..
..#.#..##.....##..#.#..
..#.#..#.......#..#.#..
..#.#..#...#...#..#.#..
..#.#..#.......#..#.#..
..#.#..#......##..#.#..
..#..#.......##..#..#..
..#..##...####..##..#..
..#...##.......##...#..
..#....##.....##....#..
...##....#####....##...
.....##.........##.....
.......##.....##.......
.........##.##.........
...........#...........`;

function gridToRects(grid: string): { x: number; y: number }[] {
  return grid
    .trim()
    .split("\n")
    .flatMap((row, y) =>
      [...row].flatMap((ch, x) => (ch === "#" ? [{ x, y }] : []))
    );
}

const SEAL_RECTS = gridToRects(SEAL_GRID);

function SealMark({ size, className }: { size: number; className?: string }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 23 23"
      shapeRendering="crispEdges"
      aria-hidden="true"
      focusable="false"
    >
      {SEAL_RECTS.map(({ x, y }) => (
        <rect
          key={`${x}-${y}`}
          x={x}
          y={y}
          width="1"
          height="1"
          fill="currentColor"
        />
      ))}
    </svg>
  );
}

// Small pixel glyphs used in verdicts and buttons.
const GLYPH_GRIDS = {
  check: `
......#
.....##
....##.
#..##..
#####..
.###...
..#....`,
  cross: `
#.....#
##...##
.##.##.
..###..
.##.##.
##...##
#.....#`,
  warn: `
..###..
..###..
..###..
..###..
.......
..###..
..###..`,
  question: `
.####..
##..##.
....##.
...##..
..##...
.......
..##...`,
  down: `
..###..
..###..
..###..
#######
.#####.
..###..
...#...`,
  lines: `
.......
#######
.......
#####..
.......
#######
.......`,
  hourglass: `
#######
.#####.
..###..
...#...
..###..
.#####.
#######`,
} as const;

// Rippling pixel seal shown while a verification is in flight.
function PixelLoader() {
  return (
    <div className="loader" role="status" aria-live="polite">
      <svg
        viewBox="0 0 23 23"
        className="loader-seal"
        shapeRendering="crispEdges"
        aria-hidden="true"
        focusable="false"
      >
        {SEAL_RECTS.map(({ x, y }) => (
          <rect
            key={`${x}-${y}`}
            x={x}
            y={y}
            width="1"
            height="1"
            fill="currentColor"
            className="loader-px"
            style={{
              animationDelay: `${Math.round(
                Math.hypot(x - 11, y - 11) * 90
              )}ms`,
            }}
          />
        ))}
      </svg>
      <div className="armor-line">-----VERIFYING-----</div>
      <span className="sr-only">Verifying…</span>
    </div>
  );
}

function PixelGlyph({ kind }: { kind: keyof typeof GLYPH_GRIDS }) {
  const rows = GLYPH_GRIDS[kind].trim().split("\n");
  return (
    <svg
      viewBox={`0 0 ${rows[0].length} ${rows.length}`}
      className="pixel-glyph"
      shapeRendering="crispEdges"
      aria-hidden="true"
      focusable="false"
    >
      {gridToRects(GLYPH_GRIDS[kind]).map(({ x, y }) => (
        <rect
          key={`${x}-${y}`}
          x={x}
          y={y}
          width="1"
          height="1"
          fill="currentColor"
        />
      ))}
    </svg>
  );
}

function groupFingerprint(hex: string): string {
  return hex.replace(/(.{4})/g, "$1 ").trim();
}

function formatDate(iso: string): string {
  if (iso === "never" || iso === "unknown") return iso;
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toUTCString();
}

function Fingerprint({ hex }: { hex: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="fp-wrap">
      <code className="fingerprint">{groupFingerprint(hex)}</code>
      <button
        type="button"
        className="copy-btn"
        onClick={() => {
          navigator.clipboard.writeText(hex).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          });
        }}
      >
        {copied ? "copied" : "copy"}
      </button>
    </span>
  );
}

function KeyCard({ info }: { info: KeyInfo }) {
  return (
    <div className="key-card">
      <div className="key-head">
        <span className="key-algo">{info.algorithm}</span>
        {info.revoked && <span className="badge badge-bad">revoked</span>}
        {info.expired && <span className="badge badge-warn">expired</span>}
      </div>
      <dl>
        <dt>Fingerprint</dt>
        <dd>
          <Fingerprint hex={info.fingerprint} />
        </dd>
        <dt>Key ID</dt>
        <dd>
          <code>{info.keyId}</code>
        </dd>
        <dt>Created</dt>
        <dd>{formatDate(info.created)}</dd>
        <dt>Expires</dt>
        <dd>{formatDate(info.expires)}</dd>
        <dt>User IDs</dt>
        <dd>
          {info.userIds.length === 0 ? (
            <em>none</em>
          ) : (
            <ul className="uid-list">
              {info.userIds.map((uid) => (
                <li key={uid}>{uid}</li>
              ))}
            </ul>
          )}
        </dd>
        {info.subkeys.length > 0 && (
          <>
            <dt>Subkeys</dt>
            <dd>
              <ul className="uid-list">
                {info.subkeys.map((sk) => (
                  <li key={sk.fingerprint}>
                    <code>{sk.keyId}</code> — {sk.algorithm}
                  </li>
                ))}
              </ul>
            </dd>
          </>
        )}
      </dl>
    </div>
  );
}

const SIG_LABEL: Record<
  SignatureInfo["status"],
  { glyph: keyof typeof GLYPH_GRIDS; text: string }
> = {
  valid: { glyph: "check", text: "Valid signature" },
  invalid: { glyph: "cross", text: "INVALID signature" },
  "no-matching-key": {
    glyph: "question",
    text: "Signature from a different key",
  },
};

// Each result gets a tone: its own color, glyph, eyebrow label, and entrance
// animation, so an invalid signature, a missing key, a malformed file, and a
// keyserver outage never look like the same generic error.
type Tone = "verified" | "invalid" | "caution" | "nokey" | "input" | "service";

const TONE_META: Record<
  Tone,
  { eyebrow: string; glyph: keyof typeof GLYPH_GRIDS }
> = {
  verified: { eyebrow: "Verified", glyph: "check" },
  invalid: { eyebrow: "Invalid signature", glyph: "cross" },
  caution: { eyebrow: "Caution", glyph: "warn" },
  nokey: { eyebrow: "No key found", glyph: "question" },
  input: { eyebrow: "Check your input", glyph: "lines" },
  service: { eyebrow: "Temporary issue", glyph: "hourglass" },
};

function errorTone(kind?: string): Tone {
  switch (kind) {
    case "invalid-email":
    case "not-clearsigned":
      return "input";
    case "no-key":
      return "nokey";
    default:
      // keyserver-unavailable, key-parse, verify-failed, unexpected, network
      return "service";
  }
}

function ResultBanner({
  tone,
  message,
  eyebrow,
}: {
  tone: Tone;
  message: string;
  eyebrow?: string;
}) {
  const meta = TONE_META[tone];
  return (
    <div className={`rb rb-${tone}`} role="status" aria-live="polite">
      <span className="rb-glyph" aria-hidden="true">
        <PixelGlyph kind={meta.glyph} />
      </span>
      <div className="rb-body">
        <div className="rb-eyebrow">{eyebrow ?? meta.eyebrow}</div>
        <div className="rb-msg">{message}</div>
      </div>
    </div>
  );
}

// Full-page Matrix rain that fills, then a glowing blade-edge wipes upward to
// reveal the newly themed page in sync. Slow and deliberate. Pure canvas.
function MatrixRain({
  fromDark,
  onFlip,
  onDone,
}: {
  fromDark: boolean;
  onFlip: () => void;
  onDone: () => void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const edgeRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const edge = edgeRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) {
      onFlip();
      onDone();
      return;
    }

    // The rain wears the theme it's leaving: dark rain when leaving dark,
    // light rain (light veil, dark-teal glyphs) when leaving light.
    const palette = fromDark
      ? { bg: "rgba(4, 12, 10, 0.16)", lead: "#eafffb", trail: "#2fe3cd" }
      : { bg: "rgba(228, 240, 238, 0.2)", lead: "#06403a", trail: "#159c8e" };

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let width = window.innerWidth;
    let height = window.innerHeight;
    const resize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.textBaseline = "top";
    };
    resize();
    canvas.style.clipPath = "inset(0 0 0 0)";
    canvas.style.opacity = "0"; // start invisible; the intro fades it in
    window.addEventListener("resize", resize);

    const fontSize = Math.max(15, Math.round(width / 62));
    const step = fontSize * 1.8;
    const cols = Math.ceil(width / step);
    const drops = Array.from({ length: cols }, () => Math.random() * -26);
    const HEX = "0123456789ABCDEF";
    const pair = () =>
      HEX[(Math.random() * 16) | 0] + HEX[(Math.random() * 16) | 0];

    const INTRO = 380; // rain fades in smoothly over the page (no hard cut)
    const FILL = 830; // rain fully up, then the reveal begins
    const WIPE = 1150; // reveal chases the rain DOWNWARD, top -> bottom
    const start = performance.now();
    let flipped = false;
    let raf = 0;

    const frame = (now: number) => {
      const t = now - start;
      // Smooth intro: ease the whole overlay in rather than snapping to a dark
      // screen on the first frame.
      if (t < INTRO) {
        const e = t / INTRO;
        canvas.style.opacity = (e * e * (3 - 2 * e)).toFixed(3); // smoothstep
      } else {
        canvas.style.opacity = "1";
      }

      ctx.fillStyle = palette.bg;
      ctx.fillRect(0, 0, width, height);
      ctx.font = `700 ${fontSize}px monospace`;
      for (let i = 0; i < cols; i++) {
        const x = i * step;
        const y = drops[i] * fontSize;
        ctx.fillStyle = palette.lead;
        ctx.fillText(pair(), x, y);
        ctx.fillStyle = palette.trail;
        ctx.fillText(pair(), x, y - fontSize);
        if (y > height && Math.random() > 0.975) drops[i] = Math.random() * -8;
        drops[i] += 0.42 + Math.random() * 0.3;
      }

      if (t >= FILL) {
        if (!flipped) {
          flipped = true;
          onFlip();
        }
        const wp = Math.min((t - FILL) / WIPE, 1);
        const eased = wp < 0.5 ? 2 * wp * wp : 1 - Math.pow(-2 * wp + 2, 2) / 2;
        // Clip the TOP of the rain away so the new theme is revealed from the
        // top downward, chasing the falling rain instead of fighting it.
        canvas.style.clipPath = `inset(${eased * 100}% 0 0 0)`;
        if (edge) {
          edge.style.opacity = wp < 1 ? "1" : "0";
          edge.style.top = `${eased * height}px`;
        }
        if (wp >= 1) {
          window.removeEventListener("resize", resize);
          onDone();
          return;
        }
      }
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, [fromDark, onFlip, onDone]);

  return (
    <>
      <canvas ref={canvasRef} className="matrix-overlay" aria-hidden="true" />
      <div ref={edgeRef} className="wipe-edge" aria-hidden="true" />
    </>
  );
}

export default function Home() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [netError, setNetError] = useState<string | null>(null);
  const [matrixActive, setMatrixActive] = useState(false);
  const [matrixFromDark, setMatrixFromDark] = useState(true);
  const fileInput = useRef<HTMLInputElement>(null);

  // Session-only theme override: an explicit data-theme wins over the OS
  // setting (see globals.css); nothing is persisted, so a reload reverts to
  // the system preference.
  const flipTheme = useCallback(() => {
    const root = document.documentElement;
    const explicit = root.getAttribute("data-theme");
    const isDark = explicit
      ? explicit === "dark"
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.setAttribute("data-theme", isDark ? "light" : "dark");
  }, []);

  const endMatrix = useCallback(() => setMatrixActive(false), []);

  const onLogoClick = useCallback(() => {
    if (matrixActive) return;
    const explicit = document.documentElement.getAttribute("data-theme");
    const isDark = explicit
      ? explicit === "dark"
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      flipTheme();
      return;
    }
    setMatrixFromDark(isDark);
    setMatrixActive(true);
  }, [matrixActive, flipTheme]);

  async function onFileChosen(file: File) {
    if (file.size > 2 * 1024 * 1024) {
      setNetError("File is larger than the 2 MB limit.");
      return;
    }
    // Windows tools often save as UTF-16; File.text() always decodes UTF-8,
    // which would turn the file into invisible mojibake. Sniff the encoding.
    const buf = new Uint8Array(await file.arrayBuffer());
    let encoding = "utf-8";
    if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) encoding = "utf-16le";
    else if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) encoding = "utf-16be";
    let text = new TextDecoder(encoding).decode(buf);
    if (encoding === "utf-8" && text.includes("\u0000")) {
      // BOM-less UTF-16: NUL at even byte index means big-endian
      text = new TextDecoder(buf[0] === 0 ? "utf-16be" : "utf-16le").decode(buf);
    }
    setMessage(text);
    setFileName(file.name);
    setNetError(null);
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (message === "") {
      setNetError("Load a clearsigned file first.");
      return;
    }
    // Mirror the server's byte-based gate so users get an honest error even
    // though JSON escaping inflates the request body.
    if (new TextEncoder().encode(message).length > 2 * 1024 * 1024) {
      setNetError("Message is larger than the 2 MB limit.");
      return;
    }
    setLoading(true);
    setResult(null);
    setNetError(null);
    try {
      const res = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, message }),
      });
      const data: VerifyResult = await res.json();
      setResult(data);
    } catch (err) {
      setNetError(
        `Request failed: ${err instanceof Error ? err.message : String(err)}`
      );
    } finally {
      setLoading(false);
    }
  }

  // "good" only when a signature verified, nothing failed, the signing key is
  // still healthy today, AND the key came from an ownership-verifying source.
  // Anything else with a valid signature gets the amber caution state.
  const validSigs =
    result?.signatures?.filter((s) => s.status === "valid") ?? [];
  const hkpUnverified =
    result?.ok === true &&
    result.anyValid === true &&
    result.keyserverVerifiesOwnership === false;
  const verdict =
    result &&
    (!result.ok
      ? "error"
      : !result.anyValid
      ? "bad"
      : result.anyInvalid || result.validButUntrustedKey || hkpUnverified
      ? "caution"
      : "good");

  const matchedFprs = [
    ...new Set(validSigs.map((s) => s.matchedFingerprint).filter(Boolean)),
  ] as string[];
  const keyCount = result?.keys?.length ?? 0;

  function goodBannerText(): string {
    const keyIds = matchedFprs.map((f) => f.slice(-16)).join(", ");
    if (keyCount > 1) {
      return `Signature is VALID — made by key ${keyIds}, one of ${keyCount} keys the keyserver returned for ${result?.email}. Check the fingerprint below.`;
    }
    return `Signature is VALID and matches the key found for ${result?.email}`;
  }

  function downloadContent() {
    if (!result?.signedText) return;
    // Name the file after the uploaded one, minus the armor extension.
    const base = fileName?.replace(/\.(asc|sig|pgp|gpg)$/i, "");
    const name = base && base.length > 0 ? base : "verified-content.txt";
    const blob = new Blob([result.signedText], {
      type: "text/plain;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }

  function cautionBannerText(): string {
    const parts: string[] = [];
    if (validSigs.some((s) => s.signerRevoked)) {
      parts.push(
        "the signing key has since been REVOKED — do not trust this without out-of-band confirmation"
      );
    }
    if (validSigs.some((s) => s.signerExpired)) {
      parts.push("the signing key has since EXPIRED");
    }
    if (result?.anyInvalid) {
      parts.push("another signature on this message FAILED verification");
    }
    if (hkpUnverified) {
      parts.push(
        "the key came from keyserver.ubuntu.com, which does NOT verify email ownership — anyone can upload a key under this address, so confirm the fingerprint out of band"
      );
    }
    return `A signature is cryptographically valid, but ${parts.join("; and ")}.`;
  }

  return (
    <>
    <div className="bg-grad" aria-hidden="true" />
    <div className="bg-field" aria-hidden="true" />
    <div className="bg-grain" aria-hidden="true" />
    <main>
      <header className="masthead">
        <button
          type="button"
          className="masthead-seal"
          onClick={onLogoClick}
          aria-label="Switch color theme"
          title="Switch theme"
        >
          <span className="seal-glint" aria-hidden="true" />
          <SealMark size={52} />
        </button>
        <h1>PGP Checker</h1>
      </header>
      <div className="armor-line armor-top">-----BEGIN VERIFICATION-----</div>
      <form onSubmit={onSubmit} className="card">
        <label htmlFor="email">Signer&apos;s email address</label>
        <input
          id="email"
          type="email"
          required
          placeholder="someone@example.org"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="email"
        />

        <label>Clearsigned file</label>
        <div className="form-row">
          <button
            type="button"
            className="secondary"
            onClick={() => fileInput.current?.click()}
          >
            {fileName ? "Change file…" : "Load from file…"}
          </button>
          {fileName && <span className="file-name">{fileName}</span>}
          <input
            ref={fileInput}
            type="file"
            hidden
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) onFileChosen(f);
              e.target.value = "";
            }}
          />
          <button
            type="submit"
            disabled={loading || message === ""}
            className="primary"
          >
            {loading ? "Verifying…" : "Verify"}
          </button>
        </div>
      </form>

      {loading && <PixelLoader />}

      {netError && (
        <ResultBanner
          tone="service"
          eyebrow="Connection problem"
          message={netError}
        />
      )}

      {result && (
        <section className="results">
          <ResultBanner
            tone={
              verdict === "good"
                ? "verified"
                : verdict === "caution"
                ? "caution"
                : verdict === "bad"
                ? "invalid"
                : errorTone(result.errorKind)
            }
            message={
              verdict === "good"
                ? goodBannerText()
                : verdict === "caution"
                ? cautionBannerText()
                : verdict === "bad"
                ? `Signature did NOT verify against the key found for ${result.email}`
                : result.error ?? "Verification failed."
            }
          />

          {result.warnings?.map((w) => (
            <ResultBanner key={w} tone="caution" eyebrow="Note" message={w} />
          ))}

          {result.keyserver && (
            <p className="keyserver-line">
              Key source: <strong>{result.keyserver}</strong>
              {result.keyserverNote && (
                <span className="hint"> — {result.keyserverNote}</span>
              )}
            </p>
          )}

          {result.signatures && result.signatures.length > 0 && (
            <div className="card">
              <h2>Signatures</h2>
              <ul className="sig-list">
                {result.signatures.map((sig, i) => (
                  <li
                    key={i}
                    className={`sig sig-${
                      sig.status === "valid" &&
                      (sig.signerRevoked || sig.signerExpired)
                        ? "caution"
                        : sig.status
                    }`}
                  >
                    <div className="sig-status">
                      <PixelGlyph kind={SIG_LABEL[sig.status].glyph} />{" "}
                      {SIG_LABEL[sig.status].text}
                      {sig.status === "valid" && sig.signerRevoked && (
                        <span className="badge badge-bad">key now revoked</span>
                      )}
                      {sig.status === "valid" && sig.signerExpired && (
                        <span className="badge badge-warn">key now expired</span>
                      )}
                    </div>
                    <div className="sig-meta">
                      by key ID <code>{sig.keyId}</code>
                      {sig.created && <> · signed {formatDate(sig.created)}</>}
                    </div>
                    {sig.matchedFingerprint && (
                      <div className="sig-meta">
                        key fingerprint:{" "}
                        <Fingerprint hex={sig.matchedFingerprint} />
                      </div>
                    )}
                    {sig.detail && (
                      <div className="sig-detail">{sig.detail}</div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.keys && result.keys.length > 0 && (
            <div className="card">
              <h2>
                {result.keys.length === 1
                  ? "Key found for this email"
                  : `${result.keys.length} keys found for this email`}
              </h2>
              {result.keys.map((k) => (
                <KeyCard key={k.fingerprint} info={k} />
              ))}
            </div>
          )}

          {(verdict === "good" || verdict === "caution") &&
            result.signedText !== undefined &&
            result.signedText !== "" && (
              <div className="card">
                <h2>Verified content</h2>
                <div className="download-row">
                  <button
                    type="button"
                    className="primary"
                    onClick={downloadContent}
                  >
                    <PixelGlyph kind="down" /> Download content
                  </button>
                  <span className="hint">
                    Saves the signed content exactly as verified, without the
                    PGP armor.
                  </span>
                </div>
              </div>
            )}
        </section>
      )}

      <footer>
        <div className="armor-line">-----END VERIFICATION-----</div>
      </footer>
    </main>
    {matrixActive && (
      <MatrixRain
        fromDark={matrixFromDark}
        onFlip={flipTheme}
        onDone={endMatrix}
      />
    )}
    </>
  );
}

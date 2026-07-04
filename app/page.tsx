"use client";

import { useRef, useState } from "react";

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
  warnings?: string[];
  signedText?: string;
}

function SealMark({ size, className }: { size: number; className?: string }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 48 48"
      aria-hidden="true"
      focusable="false"
    >
      <path
        d="M24 4 L6.7 14 V34 L24 44 L41.3 34 V14 Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinejoin="round"
      />
      <circle
        cx="24"
        cy="24"
        r="14.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeDasharray="30 9 18 12"
        transform="rotate(-35 24 24)"
      />
      <circle
        cx="24"
        cy="24"
        r="9.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeDasharray="20 7 12 8"
        transform="rotate(70 24 24)"
      />
      <circle
        cx="24"
        cy="24"
        r="5"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeDasharray="14 5 6 4"
        transform="rotate(180 24 24)"
      />
      <circle cx="24" cy="24" r="1.6" fill="currentColor" />
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

const SIG_LABEL: Record<SignatureInfo["status"], string> = {
  valid: "✔ Valid signature",
  invalid: "✘ INVALID signature",
  "no-matching-key": "? Signature from a different key",
};

export default function Home() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VerifyResult | null>(null);
  const [netError, setNetError] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

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

  // "good" only when a signature verified, nothing failed, and the signing
  // key is still healthy today. Anything mixed gets the amber caution state.
  const validSigs =
    result?.signatures?.filter((s) => s.status === "valid") ?? [];
  const verdict =
    result &&
    (!result.ok
      ? "error"
      : !result.anyValid
      ? "bad"
      : result.anyInvalid || result.validButUntrustedKey
      ? "caution"
      : "good");

  const matchedFprs = [
    ...new Set(validSigs.map((s) => s.matchedFingerprint).filter(Boolean)),
  ] as string[];
  const keyCount = result?.keys?.length ?? 0;

  function goodBannerText(): string {
    const keyIds = matchedFprs.map((f) => f.slice(-16)).join(", ");
    if (keyCount > 1) {
      return `✔ Signature is VALID — made by key ${keyIds}, one of ${keyCount} keys the keyserver returned for ${result?.email}. Check the fingerprint below.`;
    }
    return `✔ Signature is VALID and matches the key found for ${result?.email}`;
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
    return `⚠ A signature is cryptographically valid, but ${parts.join("; and ")}.`;
  }

  return (
    <main>
      <div className="watermark" aria-hidden="true">
        <SealMark size={520} />
      </div>

      <header className="masthead">
        <span className="masthead-seal">
          <SealMark size={44} />
        </span>
        <div>
          <h1>GPG Checker</h1>
          <div className="armor-line">-----BEGIN VERIFICATION-----</div>
        </div>
      </header>
      <p className="subtitle">
        Enter an email address and load a clearsigned file. The signer&apos;s
        public key is looked up on{" "}
        <a href="https://keys.openpgp.org" target="_blank" rel="noreferrer">
          keys.openpgp.org
        </a>{" "}
        (falling back to keyserver.ubuntu.com), its fingerprint is shown, and
        the signature is verified against it.
      </p>

      <form onSubmit={onSubmit} className="card">
        <h2>Verify a file</h2>
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

        <label>
          Clearsigned file{" "}
          <span className="hint">
            (contains &ldquo;-----BEGIN PGP SIGNED MESSAGE-----&rdquo;)
          </span>
        </label>
        <div className="form-row">
          <button
            type="button"
            className="secondary"
            onClick={() => fileInput.current?.click()}
          >
            {fileName ? "Choose a different file…" : "Load from file…"}
          </button>
          <span className="file-name">
            {fileName ?? "no file loaded"}
          </span>
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

      {netError && <div className="banner banner-error">{netError}</div>}

      {result && (
        <section className="results">
          <div
            className={
              verdict === "good"
                ? "banner banner-good"
                : verdict === "caution"
                ? "banner banner-warn"
                : verdict === "bad"
                ? "banner banner-bad"
                : "banner banner-error"
            }
          >
            {verdict === "good" && goodBannerText()}
            {verdict === "caution" && cautionBannerText()}
            {verdict === "bad" &&
              "✘ Signature did NOT verify against the key found for " +
                result.email}
            {verdict === "error" && (result.error ?? "Verification failed.")}
          </div>

          {result.warnings?.map((w) => (
            <div key={w} className="banner banner-warn">
              ⚠ {w}
            </div>
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
                      {SIG_LABEL[sig.status]}
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
                    ⬇ Download content
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
        <p>
          Verification runs server-side with{" "}
          <a href="https://openpgpjs.org/" target="_blank" rel="noreferrer">
            OpenPGP.js
          </a>
          . Keys are fetched live from public keyservers and nothing is stored.
        </p>
      </footer>
    </main>
  );
}

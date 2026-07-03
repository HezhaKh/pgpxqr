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
}

interface VerifyResult {
  ok: boolean;
  error?: string;
  email: string;
  keyserver?: string;
  keyserverNote?: string;
  keys?: KeyInfo[];
  signatures?: SignatureInfo[];
  anyValid?: boolean;
  signedText?: string;
  signedTextTruncated?: boolean;
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
    const text = await file.text();
    setMessage(text);
    setFileName(file.name);
    setNetError(null);
  }

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
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

  const verdict =
    result && (result.ok ? (result.anyValid ? "good" : "bad") : "error");

  return (
    <main>
      <h1>GPG Checker</h1>
      <p className="subtitle">
        Enter an email address and a clearsigned message. The signer&apos;s
        public key is looked up on{" "}
        <a href="https://keys.openpgp.org" target="_blank" rel="noreferrer">
          keys.openpgp.org
        </a>{" "}
        (falling back to keyserver.ubuntu.com), its fingerprint is shown, and
        the signature is verified against it.
      </p>

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

        <label htmlFor="message">
          Clearsigned message{" "}
          <span className="hint">
            (starts with &ldquo;-----BEGIN PGP SIGNED MESSAGE-----&rdquo;)
          </span>
        </label>
        <textarea
          id="message"
          required
          spellCheck={false}
          placeholder={
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n…\n-----BEGIN PGP SIGNATURE-----\n…\n-----END PGP SIGNATURE-----"
          }
          value={message}
          onChange={(e) => {
            setMessage(e.target.value);
            setFileName(null);
          }}
        />

        <div className="form-row">
          <button
            type="button"
            className="secondary"
            onClick={() => fileInput.current?.click()}
          >
            Load from file…
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
          <button type="submit" disabled={loading} className="primary">
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
                : verdict === "bad"
                ? "banner banner-bad"
                : "banner banner-error"
            }
          >
            {verdict === "good" &&
              "✔ Signature is VALID and matches the key found for " +
                result.email}
            {verdict === "bad" &&
              "✘ Signature did NOT verify against the key found for " +
                result.email}
            {verdict === "error" && (result.error ?? "Verification failed.")}
          </div>

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
                  <li key={i} className={`sig sig-${sig.status}`}>
                    <div className="sig-status">{SIG_LABEL[sig.status]}</div>
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

          {result.signedText !== undefined && result.signedText !== "" && (
            <div className="card">
              <h2>Signed content</h2>
              <pre className="signed-text">{result.signedText}</pre>
              {result.signedTextTruncated && (
                <p className="hint">
                  Preview truncated — the full signed content was verified.
                </p>
              )}
            </div>
          )}
        </section>
      )}

      <footer>
        Verification runs server-side with{" "}
        <a href="https://openpgpjs.org/" target="_blank" rel="noreferrer">
          OpenPGP.js
        </a>
        . Keys are fetched live from public keyservers and nothing is stored.
      </footer>
    </main>
  );
}

import * as openpgp from "openpgp";

export const MAX_MESSAGE_BYTES = 2 * 1024 * 1024; // 2 MB, below Vercel's 4.5 MB request cap
// A normal key (even a multi-key HKP bundle) is well under 1 MB; SKS-flooded
// certs are tens of MB. Cap low so we neither buffer nor amplify those.
const MAX_KEYSERVER_RESPONSE_BYTES = 1 * 1024 * 1024;
const MAX_KEYS_CHECKED = 25;
const MAX_SIGNATURES_CHECKED = 10;
const KEYSERVER_TIMEOUT_MS = 6000; // per keyserver request
const TOTAL_LOOKUP_BUDGET_MS = 9000; // overall cap across both keyservers
const LOOKUP_CACHE_TTL_MS = 60_000;
const LOOKUP_CACHE_MAX_ENTRIES = 200;

// Overridable so tests can point at a local mock keyserver.
const VKS_BASE = process.env.KEYSERVER_VKS_BASE ?? "https://keys.openpgp.org";
const HKP_BASE = process.env.KEYSERVER_HKP_BASE ?? "https://keyserver.ubuntu.com";

export type Keyserver = string;

export interface SubkeyInfo {
  keyId: string;
  fingerprint: string;
  algorithm: string;
  created: string;
}

export interface KeyInfo {
  fingerprint: string;
  keyId: string;
  algorithm: string;
  created: string;
  expires: string; // ISO date, "never", or "unknown"
  expired: boolean;
  revoked: boolean;
  userIds: string[];
  subkeys: SubkeyInfo[];
}

export interface SignatureInfo {
  keyId: string;
  status: "valid" | "invalid" | "no-matching-key";
  matchedFingerprint?: string;
  created?: string;
  detail?: string;
  // For "valid" signatures: whether the signing key is usable *today*.
  // openpgp.js verifies against the key's state at signature-creation time,
  // so a since-revoked or since-expired key still verifies.
  signerRevoked?: boolean;
  signerExpired?: boolean;
}

export interface VerifyResult {
  ok: boolean;
  error?: string;
  errorKind?: "keyserver-unavailable";
  email: string;
  keyserver?: Keyserver;
  keyserverNote?: string;
  keys?: KeyInfo[];
  signatures?: SignatureInfo[];
  anyValid?: boolean;
  anyInvalid?: boolean;
  validButUntrustedKey?: boolean;
  // false when the key came from keyserver.ubuntu.com (which does not verify
  // email ownership), so the client can downgrade the verdict.
  keyserverVerifiesOwnership?: boolean;
  warnings?: string[];
  // Full verified cleartext (bounded by the 2 MB input cap), so the client
  // can offer it as a download.
  signedText?: string;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmail(email: string): boolean {
  return email.length <= 254 && EMAIL_RE.test(email);
}

async function fetchWithTimeout(
  url: string,
  timeoutMs: number
): Promise<Response> {
  return fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      // Contactable UA so keyserver operators can reach us before blocklisting.
      "User-Agent":
        "pgp-checker/1.0 (+https://gpg.hk-hk.net; openpgp.js) abuse: hezhaxe.hx@gmail.com",
    },
    cache: "no-store",
  });
}

// Read a response body but refuse to buffer more than maxBytes, so a
// flooded/poisoned key on the keyserver can't exhaust function memory.
async function readBodyLimited(
  res: Response,
  maxBytes: number
): Promise<string | null> {
  const declared = Number(res.headers.get("content-length") ?? 0);
  if (declared > maxBytes) return null;
  const reader = res.body?.getReader();
  if (!reader) {
    const text = await res.text();
    return text.length > maxBytes ? null : text;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(merged);
}

type LookupOutcome =
  | { status: "found"; armored: string; keyserver: Keyserver; verifiesOwnership: boolean }
  | { status: "not-found" }
  | { status: "unavailable"; detail: string };

// Short-TTL, size-bounded, per-instance cache so a burst of lookups for the
// same email collapses to one upstream query instead of re-hitting the
// keyservers on every request. Best-effort (serverless instances are
// ephemeral and don't share it); paired with inbound rate limiting. Only
// definitive outcomes (found / not-found) are cached, never transient errors.
type CacheableOutcome = Extract<LookupOutcome, { status: "found" | "not-found" }>;
const lookupCache = new Map<string, { outcome: CacheableOutcome; expires: number }>();

function cacheGet(email: string): CacheableOutcome | null {
  const hit = lookupCache.get(email);
  if (!hit) return null;
  if (hit.expires <= Date.now()) {
    lookupCache.delete(email);
    return null;
  }
  return hit.outcome;
}

function cacheSet(email: string, outcome: CacheableOutcome): CacheableOutcome {
  if (lookupCache.size >= LOOKUP_CACHE_MAX_ENTRIES) {
    // Evict the oldest insertion (Map preserves insertion order).
    const oldest = lookupCache.keys().next().value;
    if (oldest !== undefined) lookupCache.delete(oldest);
  }
  lookupCache.set(email, { outcome, expires: Date.now() + LOOKUP_CACHE_TTL_MS });
  return outcome;
}

// Queries one keyserver within an overall deadline. "not-found" only when the
// server answered the question (404, or a 2xx body with no key); anything else
// is an error so the caller never claims a key doesn't exist just because a
// server was down.
async function queryKeyserver(
  url: string,
  host: Keyserver,
  verifiesOwnership: boolean,
  deadline: number
): Promise<LookupOutcome> {
  const budget = Math.min(KEYSERVER_TIMEOUT_MS, deadline - Date.now());
  if (budget <= 0) {
    return { status: "unavailable", detail: `${host}: lookup deadline exceeded` };
  }
  let res: Response;
  try {
    res = await fetchWithTimeout(url, budget);
  } catch (e) {
    return {
      status: "unavailable",
      detail: `${host}: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
  if (res.status === 404) return { status: "not-found" };
  if (!res.ok) {
    return { status: "unavailable", detail: `${host}: HTTP ${res.status}` };
  }
  const armored = await readBodyLimited(res, MAX_KEYSERVER_RESPONSE_BYTES);
  if (armored === null) {
    return {
      status: "unavailable",
      detail: `${host}: response exceeded ${MAX_KEYSERVER_RESPONSE_BYTES} bytes`,
    };
  }
  if (!armored.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
    return { status: "not-found" };
  }
  return { status: "found", armored, keyserver: host, verifiesOwnership };
}

export async function lookupKeyByEmail(email: string): Promise<LookupOutcome> {
  const cached = cacheGet(email);
  if (cached) return cached;

  const encoded = encodeURIComponent(email);
  const deadline = Date.now() + TOTAL_LOOKUP_BUDGET_MS;

  // Primary: keys.openpgp.org (serves keys only for verified email addresses).
  const vks = await queryKeyserver(
    `${VKS_BASE}/vks/v1/by-email/${encoded}`,
    new URL(VKS_BASE).host,
    true,
    deadline
  );
  if (vks.status === "found") return cacheSet(email, vks);

  // Fallback: keyserver.ubuntu.com (does NOT verify email ownership).
  const hkp = await queryKeyserver(
    `${HKP_BASE}/pks/lookup?op=get&options=mr&exact=on&search=${encoded}`,
    new URL(HKP_BASE).host,
    false,
    deadline
  );
  if (hkp.status === "found") return cacheSet(email, hkp);

  // Only claim absence — and cache it — when both servers definitively said so.
  if (vks.status === "not-found" && hkp.status === "not-found") {
    return cacheSet(email, { status: "not-found" });
  }
  const details = [vks, hkp]
    .filter((o): o is Extract<LookupOutcome, { status: "unavailable" }> =>
      o.status === "unavailable"
    )
    .map((o) => o.detail)
    .join("; ");
  return { status: "unavailable", detail: details };
}

function algorithmLabel(info: {
  algorithm: string;
  bits?: number;
  curve?: string;
}): string {
  const parts = [info.algorithm];
  if (info.bits) parts.push(`${info.bits}-bit`);
  if (info.curve) parts.push(info.curve);
  return parts.join(" ");
}

function formatFingerprint(hex: string): string {
  return hex.toUpperCase();
}

async function keyExpiry(
  key: openpgp.PublicKey
): Promise<{ expires: string; expired: boolean }> {
  try {
    const exp = await key.getExpirationTime();
    if (exp === Infinity) {
      return { expires: "never", expired: false };
    }
    if (exp === null) {
      // openpgp v6 returns null (it does not throw) when the key has no valid
      // self-signature or its primary user ID is revoked — expiry is unknowable.
      return { expires: "unknown", expired: false };
    }
    const date = exp as Date;
    return { expires: date.toISOString(), expired: date.getTime() < Date.now() };
  } catch {
    // defensive: getExpirationTime is not expected to throw in openpgp v6
    return { expires: "unknown", expired: false };
  }
}

export async function describeKey(key: openpgp.PublicKey): Promise<KeyInfo> {
  const { expires, expired } = await keyExpiry(key);
  let revoked = false;
  try {
    revoked = await key.isRevoked();
  } catch {
    revoked = false;
  }
  return {
    fingerprint: formatFingerprint(key.getFingerprint()),
    keyId: key.getKeyID().toHex().toUpperCase(),
    algorithm: algorithmLabel(key.getAlgorithmInfo()),
    created: key.getCreationTime().toISOString(),
    expires,
    expired,
    revoked,
    userIds: key.getUserIDs(),
    subkeys: key.subkeys.map((sk) => ({
      keyId: sk.getKeyID().toHex().toUpperCase(),
      fingerprint: formatFingerprint(sk.getFingerprint()),
      algorithm: algorithmLabel(sk.getAlgorithmInfo()),
      created: sk.getCreationTime().toISOString(),
    })),
  };
}

function keysOwningKeyId(
  keys: openpgp.PublicKey[],
  keyIdHex: string
): openpgp.PublicKey[] {
  const target = keyIdHex.toLowerCase();
  return keys.filter(
    (k) =>
      k.getKeyID().toHex().toLowerCase() === target ||
      k.subkeys.some((sk) => sk.getKeyID().toHex().toLowerCase() === target)
  );
}

// The clearsign armor parser silently ignores anything before the BEGIN line
// and after the signature's END line — including a whole second clearsigned
// block. Reject such input outright so a "valid" verdict can never bless a
// paste that carries unverified content. Markers are matched as whole lines,
// so dash-escaped occurrences inside the signed body don't count.
function validateSingleClearsignBlock(text: string): string | null {
  const BEGIN = "-----BEGIN PGP SIGNED MESSAGE-----";
  const SIG_BEGIN = "-----BEGIN PGP SIGNATURE-----";
  const SIG_END = "-----END PGP SIGNATURE-----";
  const lines = text.split("\n").map((l) => l.replace(/\r$/, ""));
  const at = (marker: string) =>
    lines.reduce<number[]>((acc, l, i) => (l === marker ? [...acc, i] : acc), []);
  const begins = at(BEGIN);
  const sigBegins = at(SIG_BEGIN);
  const sigEnds = at(SIG_END);
  if (begins.length !== 1 || sigBegins.length !== 1 || sigEnds.length !== 1) {
    return "Input must contain exactly one clearsigned block (one signed-message header and one signature). Concatenated or nested blocks are not verified.";
  }
  if (!(begins[0] < sigBegins[0] && sigBegins[0] < sigEnds[0])) {
    return "The clearsigned block is malformed: its armor markers are out of order.";
  }
  const outside = [...lines.slice(0, begins[0]), ...lines.slice(sigEnds[0] + 1)];
  if (outside.some((l) => l.trim() !== "")) {
    return "Input has extra content before or after the clearsigned block. That content would not be covered by the signature, so it is rejected.";
  }
  return null;
}

interface SignatureCheck {
  info: SignatureInfo;
  valid: boolean;
  signerUnusableNow: boolean;
}

// openpgp does not export its per-signature VerificationResult type directly.
type SignatureVerification = openpgp.VerifyMessageResult["signatures"][number];

async function checkOneSignature(
  message: openpgp.CleartextMessage,
  sig: SignatureVerification,
  keys: openpgp.PublicKey[]
): Promise<SignatureCheck> {
  const keyIdHex = sig.keyID.toHex().toUpperCase();
  let created: string | undefined;
  try {
    const packet = await sig.signature;
    created = packet.packets[0]?.created?.toISOString();
  } catch {
    created = undefined;
  }

  const owners = keysOwningKeyId(keys, keyIdHex);
  if (owners.length === 0) {
    return {
      valid: false,
      signerUnusableNow: false,
      info: {
        keyId: keyIdHex,
        status: "no-matching-key",
        created,
        detail:
          "This signature was made by a key that is not the one found for the email.",
      },
    };
  }

  // Key IDs are only 64 bits, so several keyserver keys can claim the same
  // ID (e.g. an impostor key embedding a copy of the real signing subkey).
  // openpgp.verify binds each signature to the FIRST matching key, which
  // would let such a crafted key shadow the real one and turn a genuine
  // signature into "invalid" — so try every owning candidate independently.
  let matched: openpgp.PublicKey | undefined;
  let lastError: unknown;
  for (const owner of owners) {
    try {
      const result = await openpgp.verify({
        message,
        verificationKeys: owner,
        expectSigned: false,
      });
      const candidate = result.signatures.find(
        (s) => s.keyID.toHex().toUpperCase() === keyIdHex
      );
      if (!candidate) continue;
      await candidate.verified;
      matched = owner;
      break;
    } catch (e) {
      lastError = e;
    }
  }

  if (!matched) {
    return {
      valid: false,
      signerUnusableNow: false,
      info: {
        keyId: keyIdHex,
        status: "invalid",
        matchedFingerprint: formatFingerprint(owners[0].getFingerprint()),
        created,
        detail: lastError instanceof Error ? lastError.message : String(lastError),
      },
    };
  }

  // The signature verified against the key's state at signing time. Now check
  // whether that signer is still usable today; a soft-revoked or since-expired
  // key must not produce an unqualified "valid".
  let signerRevoked = false;
  let signerExpired = false;
  let healthDetail: string | undefined;
  try {
    await matched.getSigningKey(sig.keyID, new Date());
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (/revoked/i.test(msg)) signerRevoked = true;
    else if (/expired/i.test(msg)) signerExpired = true;
    else signerRevoked = true; // unknown unusable state: treat as untrusted
    healthDetail = `Signing key is not usable today: ${msg}`;
  }

  return {
    valid: true,
    signerUnusableNow: signerRevoked || signerExpired,
    info: {
      keyId: keyIdHex,
      status: "valid",
      matchedFingerprint: formatFingerprint(matched.getFingerprint()),
      created,
      signerRevoked,
      signerExpired,
      detail: healthDetail,
    },
  };
}

export async function verifyClearsigned(
  email: string,
  clearsignedText: string
): Promise<VerifyResult> {
  const trimmedEmail = email.trim().toLowerCase();
  if (!isValidEmail(trimmedEmail)) {
    return { ok: false, email, error: "Invalid email address." };
  }

  if (!clearsignedText.includes("-----BEGIN PGP SIGNED MESSAGE-----")) {
    return {
      ok: false,
      email: trimmedEmail,
      error:
        "Input is not a clearsigned message. It must start with '-----BEGIN PGP SIGNED MESSAGE-----'. Detached signatures and encrypted messages are not supported.",
    };
  }

  const structureError = validateSingleClearsignBlock(clearsignedText);
  if (structureError) {
    return { ok: false, email: trimmedEmail, error: structureError };
  }

  let message: openpgp.CleartextMessage;
  try {
    message = await openpgp.readCleartextMessage({
      cleartextMessage: clearsignedText,
    });
  } catch (e) {
    console.error("readCleartextMessage failed:", e);
    return {
      ok: false,
      email: trimmedEmail,
      error: "Could not parse the input as a clearsigned PGP message.",
    };
  }

  const lookup = await lookupKeyByEmail(trimmedEmail);
  if (lookup.status === "unavailable") {
    console.error("keyserver lookup unavailable:", lookup.detail);
    return {
      ok: false,
      email: trimmedEmail,
      errorKind: "keyserver-unavailable",
      error:
        "The keyservers could not be reached, so whether a key exists for this email is unknown. Please try again later.",
    };
  }
  if (lookup.status === "not-found") {
    return {
      ok: false,
      email: trimmedEmail,
      error:
        "No public key found for this email on keys.openpgp.org or keyserver.ubuntu.com.",
    };
  }

  let keys: openpgp.PublicKey[];
  try {
    keys = (await openpgp.readKeys({
      armoredKeys: lookup.armored,
    })) as openpgp.PublicKey[];
  } catch (e) {
    console.error("readKeys failed:", e);
    return {
      ok: false,
      email: trimmedEmail,
      keyserver: lookup.keyserver,
      error: "The keyserver returned data that could not be parsed as a PGP key.",
    };
  }

  if (keys.length === 0) {
    return {
      ok: false,
      email: trimmedEmail,
      keyserver: lookup.keyserver,
      error: "Keyserver response contained no usable keys.",
    };
  }

  const warnings: string[] = [];
  if (keys.length > MAX_KEYS_CHECKED) {
    warnings.push(
      `The keyserver returned ${keys.length} keys for this email; only the first ${MAX_KEYS_CHECKED} were checked.`
    );
    keys = keys.slice(0, MAX_KEYS_CHECKED);
  }

  const signatures: SignatureInfo[] = [];
  let anyValid = false;
  let anyInvalid = false;
  let validButUntrustedKey = false;
  let signedText = "";

  try {
    const result = await openpgp.verify({
      message,
      verificationKeys: keys,
      expectSigned: false,
    });
    signedText = result.data as string;

    let sigs = result.signatures;
    if (sigs.length > MAX_SIGNATURES_CHECKED) {
      warnings.push(
        `The message carries ${sigs.length} signatures; only the first ${MAX_SIGNATURES_CHECKED} were checked.`
      );
      sigs = sigs.slice(0, MAX_SIGNATURES_CHECKED);
    }

    for (const sig of sigs) {
      const check = await checkOneSignature(message, sig, keys);
      signatures.push(check.info);
      if (check.valid) {
        anyValid = true;
        if (check.signerUnusableNow) validButUntrustedKey = true;
      } else if (check.info.status === "invalid") {
        anyInvalid = true;
      }
    }
  } catch (e) {
    console.error("openpgp.verify failed:", e);
    return {
      ok: false,
      email: trimmedEmail,
      keyserver: lookup.keyserver,
      keys: await Promise.all(keys.map(describeKey)),
      error: "Signature verification failed.",
    };
  }

  const keyInfos = await Promise.all(keys.map(describeKey));

  return {
    ok: true,
    email: trimmedEmail,
    keyserver: lookup.keyserver,
    keyserverVerifiesOwnership: lookup.verifiesOwnership,
    keyserverNote: lookup.verifiesOwnership
      ? "keys.openpgp.org only serves keys whose email address was verified by the key owner."
      : "keyserver.ubuntu.com does not verify email ownership. Confirm the fingerprint through another channel before trusting it.",
    keys: keyInfos,
    signatures,
    anyValid,
    anyInvalid,
    validButUntrustedKey,
    warnings: warnings.length > 0 ? warnings : undefined,
    signedText,
  };
}

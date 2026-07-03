import * as openpgp from "openpgp";

export const MAX_MESSAGE_BYTES = 2 * 1024 * 1024; // 2 MB, below Vercel's 4.5 MB request cap
const KEYSERVER_TIMEOUT_MS = 8000;
const SIGNED_TEXT_PREVIEW_CHARS = 5000;

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
}

export interface VerifyResult {
  ok: boolean;
  error?: string;
  email: string;
  keyserver?: Keyserver;
  keyserverNote?: string;
  keys?: KeyInfo[];
  signatures?: SignatureInfo[];
  anyValid?: boolean;
  signedText?: string;
  signedTextTruncated?: boolean;
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isValidEmail(email: string): boolean {
  return email.length <= 254 && EMAIL_RE.test(email);
}

async function fetchWithTimeout(url: string): Promise<Response> {
  return fetch(url, {
    signal: AbortSignal.timeout(KEYSERVER_TIMEOUT_MS),
    headers: { "User-Agent": "gpg-checker (openpgp.js)" },
    cache: "no-store",
  });
}

export async function lookupKeyByEmail(
  email: string
): Promise<{ armored: string; keyserver: Keyserver } | null> {
  const encoded = encodeURIComponent(email);

  // Primary: keys.openpgp.org (returns keys only for verified email addresses)
  try {
    const res = await fetchWithTimeout(`${VKS_BASE}/vks/v1/by-email/${encoded}`);
    if (res.ok) {
      const armored = await res.text();
      if (armored.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
        return { armored, keyserver: new URL(VKS_BASE).host };
      }
    }
  } catch {
    // fall through to the next keyserver
  }

  // Fallback: keyserver.ubuntu.com (no email ownership verification)
  try {
    const res = await fetchWithTimeout(
      `${HKP_BASE}/pks/lookup?op=get&options=mr&exact=on&search=${encoded}`
    );
    if (res.ok) {
      const armored = await res.text();
      if (armored.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
        return { armored, keyserver: new URL(HKP_BASE).host };
      }
    }
  } catch {
    // both keyservers unreachable; caller reports key-not-found
  }

  return null;
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
    if (exp === null || exp === Infinity) {
      return { expires: "never", expired: false };
    }
    const date = exp as Date;
    return { expires: date.toISOString(), expired: date.getTime() < Date.now() };
  } catch {
    // getExpirationTime throws for keys with no valid self-signature
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

function findKeyOwningKeyId(
  keys: openpgp.PublicKey[],
  keyIdHex: string
): openpgp.PublicKey | undefined {
  const target = keyIdHex.toLowerCase();
  return keys.find(
    (k) =>
      k.getKeyID().toHex().toLowerCase() === target ||
      k.subkeys.some((sk) => sk.getKeyID().toHex().toLowerCase() === target)
  );
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

  let message: openpgp.CleartextMessage;
  try {
    message = await openpgp.readCleartextMessage({
      cleartextMessage: clearsignedText,
    });
  } catch (e) {
    return {
      ok: false,
      email: trimmedEmail,
      error: `Could not parse the clearsigned message: ${
        e instanceof Error ? e.message : String(e)
      }`,
    };
  }

  const lookup = await lookupKeyByEmail(trimmedEmail);
  if (!lookup) {
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
    return {
      ok: false,
      email: trimmedEmail,
      keyserver: lookup.keyserver,
      error: `Keyserver returned data that could not be parsed as a PGP key: ${
        e instanceof Error ? e.message : String(e)
      }`,
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

  const signatures: SignatureInfo[] = [];
  let anyValid = false;
  let signedText = "";

  try {
    const result = await openpgp.verify({
      message,
      verificationKeys: keys,
      // report invalid/unknown signatures ourselves instead of throwing
      expectSigned: false,
    });
    signedText = result.data as string;

    for (const sig of result.signatures) {
      const keyIdHex = sig.keyID.toHex().toUpperCase();
      const owner = findKeyOwningKeyId(keys, keyIdHex);
      let created: string | undefined;
      try {
        const packet = await sig.signature;
        created = packet.packets[0]?.created?.toISOString();
      } catch {
        created = undefined;
      }

      if (!owner) {
        signatures.push({
          keyId: keyIdHex,
          status: "no-matching-key",
          created,
          detail:
            "This signature was made by a key that is not the one found for the email.",
        });
        continue;
      }

      try {
        await sig.verified;
        anyValid = true;
        signatures.push({
          keyId: keyIdHex,
          status: "valid",
          matchedFingerprint: formatFingerprint(owner.getFingerprint()),
          created,
        });
      } catch (e) {
        signatures.push({
          keyId: keyIdHex,
          status: "invalid",
          matchedFingerprint: formatFingerprint(owner.getFingerprint()),
          created,
          detail: e instanceof Error ? e.message : String(e),
        });
      }
    }
  } catch (e) {
    return {
      ok: false,
      email: trimmedEmail,
      keyserver: lookup.keyserver,
      keys: await Promise.all(keys.map(describeKey)),
      error: `Signature verification failed: ${
        e instanceof Error ? e.message : String(e)
      }`,
    };
  }

  const keyInfos = await Promise.all(keys.map(describeKey));
  const truncated = signedText.length > SIGNED_TEXT_PREVIEW_CHARS;

  return {
    ok: true,
    email: trimmedEmail,
    keyserver: lookup.keyserver,
    keyserverNote:
      lookup.keyserver === "keyserver.ubuntu.com"
        ? "keyserver.ubuntu.com does not verify email ownership. Confirm the fingerprint through another channel before trusting it."
        : lookup.keyserver === "keys.openpgp.org"
        ? "keys.openpgp.org only serves keys whose email address was verified by the key owner."
        : undefined,
    keys: keyInfos,
    signatures,
    anyValid,
    signedText: truncated
      ? signedText.slice(0, SIGNED_TEXT_PREVIEW_CHARS)
      : signedText,
    signedTextTruncated: truncated,
  };
}

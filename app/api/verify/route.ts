import { NextRequest, NextResponse } from "next/server";
import { verifyClearsigned, MAX_MESSAGE_BYTES } from "@/lib/pgp";

export const runtime = "nodejs";
export const maxDuration = 30;

// Browsers set Origin honestly on cross-origin POSTs and page JS cannot forge
// it, so rejecting foreign origins stops a malicious web page from conscripting
// visitors' browsers into driving this endpoint. Non-browser clients (curl,
// scripts) send no Origin and are unaffected — this is not a security boundary
// against them, only against the free browser-botnet vector.
function originAllowed(origin: string | null): boolean {
  if (!origin) return true;
  try {
    const host = new URL(origin).hostname;
    return (
      host === "gpg.hk-hk.net" ||
      host === "pgp.hk-hk.net" ||
      host === "localhost" ||
      host === "127.0.0.1" ||
      host.endsWith(".vercel.app")
    );
  } catch {
    return false;
  }
}

export async function POST(req: NextRequest) {
  if (!originAllowed(req.headers.get("origin"))) {
    return NextResponse.json(
      { ok: false, error: "Cross-origin requests are not allowed." },
      { status: 403 }
    );
  }

  const contentType = req.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return NextResponse.json(
      { ok: false, error: "Content-Type must be application/json." },
      { status: 415 }
    );
  }

  // Coarse pre-parse guard only: JSON escaping inflates the message (~2 bytes
  // per newline), so allow 2x here; the post-parse check below is the real gate.
  const contentLength = Number(req.headers.get("content-length") ?? 0);
  if (contentLength > MAX_MESSAGE_BYTES * 2 + 4096) {
    return NextResponse.json(
      { ok: false, error: "Request too large. Maximum message size is 2 MB." },
      { status: 413 }
    );
  }

  let body: { email?: unknown; message?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { ok: false, error: "Request body must be JSON with 'email' and 'message' fields." },
      { status: 400 }
    );
  }

  const { email, message } = body;
  if (typeof email !== "string" || typeof message !== "string") {
    return NextResponse.json(
      { ok: false, error: "'email' and 'message' must both be strings." },
      { status: 400 }
    );
  }

  if (message.length > MAX_MESSAGE_BYTES) {
    return NextResponse.json(
      { ok: false, error: "Message too large. Maximum size is 2 MB." },
      { status: 413 }
    );
  }

  try {
    const result = await verifyClearsigned(email, message);
    const status = result.ok
      ? 200
      : result.errorKind === "keyserver-unavailable"
      ? 502
      : 422;
    return NextResponse.json(result, { status });
  } catch (e) {
    console.error("verify handler error:", e);
    return NextResponse.json(
      { ok: false, error: "An unexpected error occurred." },
      { status: 500 }
    );
  }
}

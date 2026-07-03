import { NextRequest, NextResponse } from "next/server";
import { verifyClearsigned, MAX_MESSAGE_BYTES } from "@/lib/pgp";

export const runtime = "nodejs";
export const maxDuration = 30;

export async function POST(req: NextRequest) {
  const contentLength = Number(req.headers.get("content-length") ?? 0);
  if (contentLength > MAX_MESSAGE_BYTES + 4096) {
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
    return NextResponse.json(result, { status: result.ok ? 200 : 422 });
  } catch (e) {
    return NextResponse.json(
      {
        ok: false,
        error: `Unexpected error: ${e instanceof Error ? e.message : String(e)}`,
      },
      { status: 500 }
    );
  }
}

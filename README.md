# GPG Checker

Verify PGP **clearsigned** messages against a signer's email address.

Give it an email and a clearsigned message (pasted or loaded from a file). It:

1. Looks up the public key for that email on [keys.openpgp.org](https://keys.openpgp.org)
   (VKS API), falling back to [keyserver.ubuntu.com](https://keyserver.ubuntu.com) (HKP API).
2. Shows the key's fingerprint, algorithm, creation/expiry dates, user IDs, and
   revocation status.
3. Verifies the clearsign signature with [OpenPGP.js](https://openpgpjs.org/) and
   reports exactly which key made each signature.

Verification runs server-side. Keys are fetched live; nothing is stored.

> **Trust note:** keyserver.ubuntu.com does not verify email ownership — anyone can
> upload a key with any email. A "valid" result there means the message was signed by
> *a* key associated with that email on the keyserver, so always confirm the displayed
> fingerprint through another channel. keys.openpgp.org results are stronger: it only
> serves keys whose email address was confirmed by the key owner.

## API

`POST /api/verify` with JSON body:

```json
{ "email": "someone@example.org", "message": "-----BEGIN PGP SIGNED MESSAGE-----..." }
```

Returns key info, per-signature verdicts (`valid` / `invalid` / `no-matching-key`),
and the signed content. Maximum message size: 2 MB.

## Development

```bash
npm install
npm run dev
```

For tests, the keyserver base URLs can be overridden with `KEYSERVER_VKS_BASE` and
`KEYSERVER_HKP_BASE` to point at a mock server.

## Deploy

Deployed on [Vercel](https://vercel.com) (Next.js App Router, Node.js runtime).

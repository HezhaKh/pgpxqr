import type { Metadata } from "next";
import { Geist, Geist_Mono, Silkscreen } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const silkscreen = Silkscreen({
  variable: "--font-pixel",
  weight: ["400", "700"],
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://gpg.hk-hk.net"),
  title: "PGP Checker",
  description:
    "Verify PGP clearsigned messages: look up a key by email, see its fingerprint, and check the signature.",
  openGraph: {
    title: "PGP Checker",
    description:
      "Verify PGP clearsigned files against a signer's email. Keyserver lookup, fingerprint, verdict.",
    images: ["/og.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "PGP Checker",
    description:
      "Verify PGP clearsigned files against a signer's email. Keyserver lookup, fingerprint, verdict.",
    images: ["/og.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} ${silkscreen.variable}`}
    >
      <body>{children}</body>
    </html>
  );
}

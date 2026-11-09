import { connection } from 'next/server';
import type { Metadata } from "next";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";
import "./globals.css";
import { isPreview, PUBLIC_ORIGIN, PRODUCT_DESCRIPTION } from '@/lib/discovery';

export const metadata: Metadata = {
  title: { default: "Zero Day Canary", template: "%s · Zero Day Canary" },
  description: PRODUCT_DESCRIPTION,
  metadataBase: new URL(PUBLIC_ORIGIN),
  robots: isPreview() ? { index: false, follow: false } : undefined,
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  await connection();
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body><aside style={{padding:16,background:"#fff3cd",color:"#172b32",fontSize:16}}>Self-hosted reference project — unmaintained. No hosted service, support or automatic advisory updates.</aside>{children}</body>
    </html>
  );
}

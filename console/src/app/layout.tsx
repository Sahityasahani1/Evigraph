import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "./providers";

export const metadata: Metadata = {
  title: "EviGraph Forensic Operations Console",
  description: "Evidence-Grounded Network Forensic Detection & Incident Response Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-evi-canvas text-evi-text antialiased min-h-screen selection:bg-evi-accent/30 selection:text-white">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ThreatGraph - Attack Graph Risk Analysis",
  description: "20% Milestone Vertical Slice: Discovery, Graph Construction, Path Scoring",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

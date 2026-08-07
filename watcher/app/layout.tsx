import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Martor Sentinel",
  description: "Starea agentului de securitate, observată din afara serverului.",
  // Fără indexare. Pagina nu e secretă, dar nu are de ce să apară în căutări.
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="ro">
      <body>{children}</body>
    </html>
  );
}

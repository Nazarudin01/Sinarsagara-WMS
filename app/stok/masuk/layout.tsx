import { Metadata } from "next";

export const metadata: Metadata = {
  title: "Stok Masuk",
  description: "Halaman untuk mengelola stok masuk",
};

export default function StokMasukLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
} 
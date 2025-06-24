"use client";

import { ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { id } from "date-fns/locale";
import { Button } from "@/components/ui/button";
import { Eye, Trash2 } from "lucide-react";
import { useToast } from "@/components/ui/use-toast";
import { useRouter } from "next/navigation";

export type StokMasuk = {
  id: string;
  nomor: string;
  tanggal: string;
  pemasok: string;
  gudang: string;
  status: string;
  total: number;
  items: {
    id: string;
    sku: string;
    nama_barang: string;
    qty: number;
    harga: number;
    satuan: string;
    jenis: string;
  }[];
  created_at: string;
  updated_at: string;
};

const handleLihatDetail = (id: string) => {
  alert(`Lihat detail stok masuk: ${id}`);
};

const handleHapus = async (id: string) => {
  if (confirm("Yakin ingin menghapus data ini?")) {
    try {
      const response = await fetch(`/api/stok-masuk/${id}`, {
        method: "DELETE",
      });

      if (!response.ok) {
        throw new Error("Gagal menghapus data");
      }

      // Refresh halaman untuk memperbarui data
      window.location.reload();
    } catch (error) {
      console.error("Error deleting stok masuk:", error);
      alert("Gagal menghapus data");
    }
  }
};

export const columns: ColumnDef<StokMasuk>[] = [
  {
    accessorKey: "tanggal",
    header: "Tanggal",
    cell: ({ row }) => {
      const date = new Date(row.getValue("tanggal"));
      return format(date, "dd MMMM yyyy", { locale: id });
    },
  },
  {
    accessorKey: "nomor",
    header: "No Transaksi",
  },
  {
    accessorKey: "pemasok",
    header: "Pemasok",
    cell: ({ row }) => row.getValue("pemasok") || "-",
  },
  {
    accessorKey: "gudang",
    header: "Gudang",
    cell: ({ row }) => row.getValue("gudang") || "-",
  },
  {
    accessorKey: "items",
    header: "Jumlah Barang",
    cell: ({ row }) => {
      const items = row.getValue("items") as StokMasuk["items"];
      return items?.length || 0;
    },
  },
  {
    accessorKey: "status",
    header: "Status",
    cell: ({ row }) => {
      const status = row.getValue("status") as string;
      return (
        <span className={`px-2 py-1 rounded-full text-xs ${
          status === "DRAFT" ? "bg-yellow-100 text-yellow-800" :
          status === "COMPLETED" ? "bg-green-100 text-green-800" :
          "bg-gray-100 text-gray-800"
        }`}>
          {status}
        </span>
      );
    },
  },
  {
    id: "aksi",
    header: "Aksi",
    cell: ({ row }) => (
      <div style={{ display: "flex", gap: 8 }}>
        <Button variant="ghost" size="icon" onClick={() => handleLihatDetail(row.original.id)}>
          <Eye className="h-4 w-4" />
        </Button>
        <Button variant="ghost" size="icon" onClick={() => handleHapus(row.original.id)}>
          <Trash2 className="h-4 w-4 text-red-500" />
        </Button>
      </div>
    ),
  },
]; 
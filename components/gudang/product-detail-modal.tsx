"use client";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import Image from "next/image";
import { toast } from "sonner";

interface Barang {
  id: string;
  stokGudangId: string;
  gambar: string;
  kodeRak: string;
  sku: string;
  nama: string;
  stok: number;
  satuan: string;
  jenis: string;
  harga: number;
}

interface ProductDetailModalProps {
  isOpen: boolean;
  onClose: () => void;
  barang: Barang | null;
  onDelete: (stokGudangId: string) => void;
  onEdit: () => void;
}

const DetailRow = ({ label, value }: { label: string; value: string | number }) => (
  <div className="grid grid-cols-3 gap-2 py-2 border-b">
    <Label className="font-semibold text-sm text-gray-600">{label}</Label>
    <div className="col-span-2 text-sm">{value}</div>
  </div>
);

export function ProductDetailModal({ isOpen, onClose, barang, onDelete, onEdit }: ProductDetailModalProps) {
  if (!barang) return null;

  const handleEdit = () => {
    onEdit();
  };

  const handleDelete = () => {
    if (confirm("Apakah Anda yakin ingin menghapus stok barang ini dari gudang?")) {
      onDelete(barang.stokGudangId);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Detail Produk</DialogTitle>
        </DialogHeader>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 py-4">
          <div className="md:col-span-1 flex flex-col items-center">
            <div className="relative w-40 h-40">
              <Image
                src={barang.gambar ? `/uploads/${barang.gambar}` : "/placeholder.png"}
                alt={barang.nama}
                fill
                className="object-cover rounded-lg border"
              />
            </div>
          </div>
          <div className="md:col-span-2 space-y-1">
            <DetailRow label="Nama Barang" value={barang.nama} />
            <DetailRow label="SKU" value={barang.sku} />
            <DetailRow label="Kode Rak" value={barang.kodeRak} />
            <DetailRow label="Stok" value={`${barang.stok} ${barang.satuan}`} />
            <DetailRow label="Jenis" value={barang.jenis} />
            <DetailRow
              label="Harga"
              value={new Intl.NumberFormat('id-ID', {
                style: 'currency',
                currency: 'IDR'
              }).format(barang.harga)}
            />
          </div>
        </div>
        <DialogFooter className="sm:justify-end gap-2">
          <Button type="button" variant="destructive" onClick={handleDelete}>
            Hapus
          </Button>
          <Button type="button" variant="secondary" onClick={handleEdit}>
            Edit
          </Button>
          <DialogClose asChild>
            <Button type="button" variant="outline">
              Tutup
            </Button>
          </DialogClose>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
} 
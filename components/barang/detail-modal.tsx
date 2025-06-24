"use client";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import type { Barang } from "@/app/master-data/barang/page";

interface BarangDetailModalProps {
  isOpen: boolean;
  onClose: () => void;
  barang: Barang | null;
}

const formatCurrency = (value: number) => {
  return new Intl.NumberFormat("id-ID", {
    style: "currency",
    currency: "IDR",
    minimumFractionDigits: 0,
  }).format(value);
};

export function BarangDetailModal({ isOpen, onClose, barang }: BarangDetailModalProps) {
  if (!barang) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Detail Barang: {barang.nama}</DialogTitle>
        </DialogHeader>
        <div className="grid grid-cols-3 gap-6 py-4">
          <div className="col-span-1">
            <img
              src={barang.gambar ? `/uploads/${barang.gambar}` : "/placeholder.png"}
              alt={barang.nama}
              className="w-full h-auto object-cover rounded-md border"
              onError={(e) => {
                const target = e.target as HTMLImageElement;
                target.src = "/placeholder.png";
              }}
            />
          </div>
          <div className="col-span-2 space-y-3">
            <div>
              <p className="text-sm text-muted-foreground">SKU</p>
              <p className="font-semibold">{barang.sku}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Nama Barang</p>
              <p className="font-semibold">{barang.nama}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Kategori</p>
              <Badge variant="outline">{barang.kategori}</Badge>
            </div>
             <div>
              <p className="text-sm text-muted-foreground">Satuan & Jenis</p>
              <div className="flex gap-2">
                <Badge>{barang.satuan}</Badge>
                <Badge variant="secondary">{barang.jenis}</Badge>
              </div>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Harga Beli</p>
              <p className="font-semibold text-lg text-primary">
                {formatCurrency(barang.hargaBeli)}
              </p>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button onClick={onClose} variant="outline">Tutup</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
} 
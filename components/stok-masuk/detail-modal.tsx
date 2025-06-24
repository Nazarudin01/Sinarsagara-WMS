"use client";

import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { format } from "date-fns";
import { id } from "date-fns/locale";

interface Item {
  id: string;
  sku: string;
  nama_barang: string;
  qty: number;
  harga: number;
  satuan?: string;
  kodeRak?: { kode: string } | null;
}

interface StokMasukDetail {
  id: string;
  nomor: string;
  tanggal: string;
  pemasok: string;
  gudang: string;
  items: Item[];
}

interface DetailModalProps {
  isOpen: boolean;
  onClose: () => void;
  data: StokMasukDetail | null;
  getNamaPemasok: (id: string) => string;
  getNamaGudang: (id: string) => string;
}

export function StokMasukDetailModal({ isOpen, onClose, data, getNamaPemasok, getNamaGudang }: DetailModalProps) {
  if (!data) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Detail Stok Masuk</DialogTitle>
        </DialogHeader>
        <div className="space-y-2">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-xs text-muted-foreground">Tanggal Masuk</div>
              <div className="font-medium">{format(new Date(data.tanggal), "dd MMMM yyyy", { locale: id })}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">No Transaksi</div>
              <div className="font-medium">{data.nomor}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Pemasok</div>
              <div className="font-medium">{getNamaPemasok(data.pemasok)}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground">Gudang</div>
              <div className="font-medium">{getNamaGudang(data.gudang)}</div>
            </div>
          </div>
          <div className="mt-4">
            <div className="font-semibold mb-2">Tabel Item</div>
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm border">
                <thead>
                  <tr className="bg-muted">
                    <th className="px-2 py-1 border">Kode Rak</th>
                    <th className="px-2 py-1 border">Barang</th>
                    <th className="px-2 py-1 border">Jumlah</th>
                    <th className="px-2 py-1 border">Satuan</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={item.id}>
                      <td className="px-2 py-1 border text-center">{item.kodeRak?.kode || '-'}</td>
                      <td className="px-2 py-1 border">{item.nama_barang}</td>
                      <td className="px-2 py-1 border text-center">{item.qty}</td>
                      <td className="px-2 py-1 border text-center">{item.satuan || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button onClick={onClose} type="button" variant="outline">Tutup</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
} 
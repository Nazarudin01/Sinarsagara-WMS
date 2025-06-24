"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Search, Download, Eye, Trash2, AlertTriangle } from "lucide-react";
import { toast } from "sonner";
import { useDebounce } from "@/hooks/use-debounce";
import Image from "next/image";
import { ProductDetailModal } from "@/components/gudang/product-detail-modal";
import { EditRakModal } from "@/components/gudang/edit-rak-modal";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { useRouter } from "next/navigation";

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

export default function GudangDetailPage({ params }: { params: { id: string } }) {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState("");
  const [gudang, setGudang] = useState<any>(null);
  const [barangs, setBarangs] = useState<Barang[]>([]);
  const debouncedSearch = useDebounce(searchQuery, 300);

  // State for detail modal
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);
  const [selectedBarang, setSelectedBarang] = useState<Barang | null>(null);

  // State for edit rak modal
  const [isEditRakModalOpen, setIsEditRakModalOpen] = useState(false);
  const [availableRaks, setAvailableRaks] = useState([]);

  // State for delete gudang modal
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);

  // Fetch all available raks for the edit modal
  useEffect(() => {
    const fetchAllRaks = async () => {
      try {
        const res = await fetch('/api/master-data/kode-rak');
        const data = await res.json();
        setAvailableRaks(data.data || []);
      } catch (error) {
        console.error("Failed to fetch all raks", error);
      }
    };
    fetchAllRaks();
  }, []);

  // Fetch gudang detail
  useEffect(() => {
    const fetchGudang = async () => {
      try {
        const res = await fetch(`/api/master-data/gudang/${params.id}`);
        if (!res.ok) throw new Error("Failed to fetch gudang");
        const data = await res.json();
        setGudang(data);
      } catch (error) {
        console.error("Error fetching gudang:", error);
        toast.error("Gagal memuat data gudang");
      }
    };
    fetchGudang();
  }, [params.id]);

  // Fetch barangs
  useEffect(() => {
    const fetchBarangs = async () => {
      try {
        const url = debouncedSearch
          ? `/api/master-data/gudang/${params.id}/barang?q=${encodeURIComponent(debouncedSearch)}`
          : `/api/master-data/gudang/${params.id}/barang`;
        const res = await fetch(url);
        if (!res.ok) throw new Error("Failed to fetch barangs");
        const data = await res.json();
        setBarangs(data);
      } catch (error) {
        console.error("Error fetching barangs:", error);
        toast.error("Gagal memuat data barang");
      }
    };
    fetchBarangs();
  }, [params.id, debouncedSearch]);

  const handleOpenDetail = (barang: Barang) => {
    setSelectedBarang(barang);
    setIsDetailModalOpen(true);
  };

  const handleOpenEditRak = () => {
    setIsDetailModalOpen(false); // Close detail modal
    setIsEditRakModalOpen(true); // Open edit modal
  };

  const handleUpdateRak = async (newRakId: string) => {
    if (!selectedBarang) return;

    try {
      const response = await fetch(`/api/stok-gudang/${selectedBarang.stokGudangId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kodeRakId: newRakId }),
      });

      if (!response.ok) throw new Error('Gagal memperbarui rak');

      // Update UI
      const updatedBarang = await response.json();
      const newRak = availableRaks.find(r => r.id === newRakId);
      setBarangs(prev => 
        prev.map(b => 
          b.stokGudangId === selectedBarang.stokGudangId 
            ? { ...b, kodeRak: newRak?.kode || b.kodeRak } 
            : b
        )
      );
      toast.success("Kode Rak berhasil diperbarui.");

    } catch (error) {
      toast.error("Gagal memperbarui Kode Rak.");
    } finally {
      setIsEditRakModalOpen(false);
    }
  };

  const handleDeleteStokGudang = async (stokGudangId: string) => {
    try {
      const response = await fetch(`/api/stok-gudang/${stokGudangId}`, {
        method: "DELETE",
      });

      if (!response.ok) {
        throw new Error("Gagal menghapus stok barang");
      }

      // Hapus barang dari state untuk update UI secara real-time
      setBarangs(prev => prev.filter(b => b.stokGudangId !== stokGudangId));
      toast.success("Stok barang berhasil dihapus dari gudang.");
      
    } catch (error) {
      toast.error("Gagal menghapus stok barang.");
      console.error("Error deleting stock:", error);
    } finally {
      setIsDetailModalOpen(false);
    }
  };

  const handleExport = async () => {
    try {
      const res = await fetch(`/api/master-data/gudang/${params.id}/export`);
      if (!res.ok) throw new Error("Failed to export data");
      
      // Create blob from response
      const blob = await res.blob();
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `gudang-${gudang?.kode}-${new Date().toISOString().split('T')[0]}.xlsx`;
      document.body.appendChild(a);
      a.click();
      
      // Cleanup
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      toast.success("Data berhasil diekspor");
    } catch (error) {
      console.error("Error exporting data:", error);
      toast.error("Gagal mengekspor data");
    }
  };

  const handleDeleteGudang = async () => {
    try {
      const response = await fetch(`/api/master/gudang/${params.id}`, {
        method: "DELETE",
      });

      if (!response.ok) {
        throw new Error("Gagal menghapus gudang");
      }
      
      toast.success(`Gudang "${gudang?.nama}" berhasil dihapus.`);
      router.push("/master/gudang");

    } catch (error) {
      toast.error("Gagal menghapus gudang.");
      console.error("Error deleting gudang:", error);
    } finally {
      setIsDeleteModalOpen(false);
    }
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold">{gudang?.nama}</h1>
          <p className="text-gray-500">{gudang?.kode} - {gudang?.kategori}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={handleExport} variant="outline" className="border-blue-500 text-blue-500 hover:bg-blue-100 hover:text-blue-600">
            <Download className="w-4 h-4 mr-2" />
            Export Data
          </Button>
          <Button onClick={() => setIsDeleteModalOpen(true)} className="bg-red-600 hover:bg-red-700 text-white">
            <Trash2 className="w-4 h-4 mr-2" />
            Hapus Gudang
          </Button>
        </div>
      </div>

      <div className="flex items-center space-x-2 mb-4">
        <div className="relative w-64">
          <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Cari barang..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-8 h-9 rounded-full"
          />
        </div>
      </div>

      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Gambar</TableHead>
              <TableHead>Kode Rak</TableHead>
              <TableHead>SKU</TableHead>
              <TableHead>Nama Barang</TableHead>
              <TableHead>Stok</TableHead>
              <TableHead>Satuan</TableHead>
              <TableHead>Jenis</TableHead>
              <TableHead>Harga</TableHead>
              <TableHead className="text-right">Aksi</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {barangs.map((barang) => (
              <TableRow key={barang.stokGudangId}>
                <TableCell>
                  <div className="relative w-12 h-12">
                    <Image
                      src={barang.gambar ? `/uploads/${barang.gambar}` : "/placeholder.png"}
                      alt={barang.nama}
                      fill
                      className="object-cover rounded-md"
                    />
                  </div>
                </TableCell>
                <TableCell>{barang.kodeRak}</TableCell>
                <TableCell>{barang.sku}</TableCell>
                <TableCell>{barang.nama}</TableCell>
                <TableCell>{barang.stok}</TableCell>
                <TableCell>{barang.satuan}</TableCell>
                <TableCell>{barang.jenis}</TableCell>
                <TableCell>
                  {new Intl.NumberFormat('id-ID', {
                    style: 'currency',
                    currency: 'IDR'
                  }).format(barang.harga)}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-emerald-600 hover:text-emerald-700 hover:bg-emerald-50"
                    onClick={() => handleOpenDetail(barang)}
                  >
                    <Eye className="w-4 h-4 mr-2" />
                    Lihat Detail
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Modals */}
      {selectedBarang && (
        <ProductDetailModal
          isOpen={isDetailModalOpen}
          onClose={() => setIsDetailModalOpen(false)}
          product={selectedBarang}
          onEditRak={handleOpenEditRak}
          onDeleteStok={handleDeleteStokGudang}
        />
      )}
      
      {selectedBarang && (
        <EditRakModal
          isOpen={isEditRakModalOpen}
          onClose={() => setIsEditRakModalOpen(false)}
          onUpdate={handleUpdateRak}
          availableRaks={availableRaks}
          currentRakId={availableRaks.find(r => r.kode === selectedBarang.kodeRak)?.id || ""}
        />
      )}

      {/* Delete Confirmation Modal */}
      <Dialog open={isDeleteModalOpen} onOpenChange={setIsDeleteModalOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <div className="flex items-center space-x-4">
              <div className="mx-auto flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
                <AlertTriangle className="h-6 w-6 text-red-600" aria-hidden="true" />
              </div>
              <DialogTitle className="text-lg font-medium leading-6 text-gray-900">
                Hapus Gudang
              </DialogTitle>
            </div>
          </DialogHeader>
          <div className="mt-2">
            <DialogDescription className="text-sm text-gray-500 pl-[56px]">
              Anda akan menghapus gudang <strong>"{gudang?.nama}"</strong>.
              <br />
              Semua data stok terkait akan terhapus permanen. Apakah Anda yakin?
            </DialogDescription>
          </div>
          <DialogFooter className="mt-4 sm:justify-end">
            <Button variant="outline" onClick={() => setIsDeleteModalOpen(false)}>
              Batal
            </Button>
            <Button
              className="bg-red-600 hover:bg-red-700 text-white"
              onClick={handleDeleteGudang}
            >
              Ya, Hapus Gudang
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
} 
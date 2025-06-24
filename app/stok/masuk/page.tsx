"use client";

import { useEffect, useState } from "react";
import { DataTable } from "@/components/ui/data-table";
import { columns as baseColumns } from "./columns";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/components/ui/use-toast";
import { Search, Upload, Plus, Eye, Trash2 } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { StokMasukFormModal } from "@/components/stok-masuk/form-modal";
import { StokMasukDetailModal } from "@/components/stok-masuk/detail-modal";
import { StokMasukImportModal } from "@/components/stok-masuk/import-modal";
import type { StokMasuk } from "./columns";

export default function StokMasukPage() {
  const [data, setData] = useState<StokMasuk[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [isModalOpen, setIsModalOpen] = useState(false);
  const { toast } = useToast();

  const [isImportModalOpen, setIsImportModalOpen] = useState(false);

  // State untuk data referensi pemasok & gudang
  const [dataPemasok, setDataPemasok] = useState<{ id: string; nama: string }[]>([]);
  const [dataGudang, setDataGudang] = useState<any[]>([]);

  const [isDetailOpen, setIsDetailOpen] = useState(false);
  const [detailData, setDetailData] = useState<any>(null);
  const [isDetailLoading, setIsDetailLoading] = useState(false);

  useEffect(() => {
    fetchData();
    fetchPemasok();
  }, []);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const response = await fetch("/api/stok-masuk");
      if (!response.ok) {
        throw new Error("Gagal mengambil data stok masuk");
      }
      const result = await response.json();
      setData(result);
    } catch (error) {
      console.error("Error fetching stok masuk:", error);
      toast({
        variant: "destructive",
        title: "Error",
        description: "Gagal mengambil data stok masuk",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const fetchPemasok = async () => {
    try {
      const [pemasokRes, gudangRes] = await Promise.all([
        fetch('/api/master-data/pemasok'),
        fetch('/api/master/gudang')
      ]);
      const pemasokData = await pemasokRes.json();
      const gudangData = await gudangRes.json();
      setDataPemasok(pemasokData.data || []);
      setDataGudang(gudangData.data || []);
    } catch (error) {
      console.error("Failed to fetch master data:", error);
    }
  };

  const getNamaPemasok = (id: string) => dataPemasok.find(p => p.id === id)?.nama || id;
  const getNamaGudang = (id: string) => dataGudang.find(g => g.id === id)?.nama || id;

  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
  };

  const handleImport = async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/stok-masuk/import', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Gagal mengimport file.');
      }

      const result = await response.json();
      toast({
        title: "Import Berhasil",
        description: result.message,
      });
      setIsImportModalOpen(false);
      fetchData(); // Refresh data
    } catch (error) {
      toast({
        title: "Error",
        description: (error as Error).message,
        variant: "destructive",
      });
    }
  };

  const handleDelete = async (id: string) => {
    // Optimistic update
    setData(prevData => prevData.filter(item => item.id !== id));

    try {
      const response = await fetch(`/api/stok-masuk/${id}`, {
        method: "DELETE",
      });

      if (!response.ok) {
        throw new Error("Gagal menghapus data");
      }

      toast({
        title: "Berhasil",
        description: "Data berhasil dihapus",
      });
    } catch (error) {
      console.error("Error deleting stok masuk:", error);
      // Revert optimistic update on error
      fetchData();
      toast({
        variant: "destructive",
        title: "Error",
        description: "Gagal menghapus data",
      });
    }
  };

  const handleLihatDetail = async (id: string) => {
    setIsDetailLoading(true);
    setIsDetailOpen(true);
    try {
      const res = await fetch(`/api/stok-masuk/${id}`);
      if (!res.ok) throw new Error("Gagal mengambil detail stok masuk");
      const data = await res.json();
      setDetailData(data);
    } catch (e) {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Gagal mengambil detail stok masuk",
      });
      setDetailData(null);
    } finally {
      setIsDetailLoading(false);
    }
  };

  // Kolom dengan mapping nama pemasok/gudang
  const columns = baseColumns.map(col => {
    if (col.accessorKey === "pemasok") {
      return {
        ...col,
        cell: ({ row }: any) => getNamaPemasok(row.getValue("pemasok")),
      };
    }
    if (col.accessorKey === "gudang") {
      return {
        ...col,
        cell: ({ row }: any) => getNamaGudang(row.getValue("gudang")),
      };
    }
    if (col.id === "aksi") {
      return {
        ...col,
        cell: ({ row }: any) => (
          <div style={{ display: "flex", gap: 8 }}>
            <Button variant="ghost" size="icon" onClick={() => handleLihatDetail(row.original.id)}>
              <Eye className="h-4 w-4" />
            </Button>
            <Button 
              variant="ghost" 
              size="icon" 
              onClick={() => handleDelete(row.original.id)}
            >
              <Trash2 className="h-4 w-4 text-red-500" />
            </Button>
          </div>
        ),
      };
    }
    return col;
  });

  const filteredData = data.filter((item) => {
    const searchLower = searchQuery.toLowerCase();
    return (
      item.nomor.toLowerCase().includes(searchLower) ||
      getNamaPemasok(item.pemasok).toLowerCase().includes(searchLower) ||
      getNamaGudang(item.gudang).toLowerCase().includes(searchLower)
    );
  });

  return (
    <div className="w-full px-6 py-10">
      <div className="flex flex-col md:flex-row justify-between items-center gap-4 mb-6">
        <h1 className="text-2xl font-bold">Stok Masuk</h1>
        <div className="flex flex-col md:flex-row gap-4 w-full md:w-auto">
          <div className="relative flex-1 md:w-[300px]">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Cari stok masuk..."
              value={searchQuery}
              onChange={handleSearch}
              className="pl-8"
            />
          </div>
          <div className="flex gap-2">
            <Button onClick={() => setIsImportModalOpen(true)} variant="outline" className="flex items-center gap-2">
              <Upload className="h-4 w-4" />
              Import
            </Button>
            <Button onClick={() => setIsModalOpen(true)} className="flex items-center gap-2">
              <Plus className="h-4 w-4" />
              Buat Stok Masuk
            </Button>
          </div>
        </div>
      </div>
      <div className="relative z-0">
        <DataTable columns={columns} data={filteredData} isLoading={isLoading} />
      </div>

      <Dialog open={isModalOpen} onOpenChange={setIsModalOpen}>
        <StokMasukFormModal
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          onSuccess={(newData) => {
            setData(prevData => [newData, ...prevData]);
            setIsModalOpen(false);
          }}
        />
      </Dialog>

      <StokMasukImportModal
        isOpen={isImportModalOpen}
        onClose={() => setIsImportModalOpen(false)}
        onImport={handleImport}
      />

      <StokMasukDetailModal
        isOpen={isDetailOpen}
        onClose={() => setIsDetailOpen(false)}
        data={detailData}
        getNamaPemasok={getNamaPemasok}
        getNamaGudang={getNamaGudang}
      />
    </div>
  );
} 
"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Plus, Upload, MoreHorizontal, ArrowUpDown, Eye } from "lucide-react";
import { useToast } from "@/components/ui/use-toast";
import { DataTable } from "@/components/barang/data-table";
import { BarangFormModal } from "@/components/barang/form-modal";
import { BarangImportModal } from "@/components/barang/import-modal";
import { BarangDetailModal } from "@/components/barang/detail-modal";
import { ColumnDef } from "@tanstack/react-table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

// Column definition moved inside page.tsx
export type Barang = {
  id: string;
  sku: string;
  nama: string;
  kategori: string;
  satuan: string;
  jenis: string;
  hargaBeli: number;
  gambar?: string;
};

interface ColumnsProps {
  onEdit: (barang: Barang) => void;
  onDelete: (id: string) => void;
  onViewDetail: (barang: Barang) => void;
}

const getColumns = ({ onEdit, onDelete, onViewDetail }: ColumnsProps): ColumnDef<Barang>[] => [
  {
    accessorKey: "gambar",
    header: "Gambar",
    cell: ({ row }) => {
      const barang = row.original;
      return (
        <div className="relative w-16 h-16">
          <img
            src={barang.gambar ? `/uploads/${barang.gambar}` : "/placeholder.png"}
            alt={barang.nama}
            className="w-full h-full object-cover rounded"
            onError={(e) => {
              const target = e.target as HTMLImageElement;
              target.src = "/placeholder.png";
            }}
          />
        </div>
      );
    },
  },
  {
    accessorKey: "sku",
    header: ({ column }) => (
      <Button
        variant="ghost"
        onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
      >
        SKU
        <ArrowUpDown className="ml-2 h-4 w-4" />
      </Button>
    ),
  },
  { accessorKey: "nama", header: "Nama Barang" },
  { accessorKey: "kategori", header: "Kategori" },
  { accessorKey: "satuan", header: "Satuan" },
  {
    accessorKey: "hargaBeli",
    header: "Harga Beli",
    cell: ({ row }) => {
      const amount = parseFloat(row.getValue("hargaBeli"));
      const formatted = new Intl.NumberFormat("id-ID", {
        style: "currency",
        currency: "IDR",
      }).format(amount);
      return <div className="font-medium">{formatted}</div>;
    },
  },
  {
    id: "actions",
    header: "Aksi",
    cell: ({ row }) => {
      const barang = row.original;
      return (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="h-8 w-8 p-0">
              <span className="sr-only">Buka menu</span>
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuLabel>Aksi</DropdownMenuLabel>
            <DropdownMenuItem onClick={() => onViewDetail(barang)}>
              <Eye className="mr-2 h-4 w-4" />
              Lihat Detail
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => onEdit(barang)}>Edit</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => onDelete(barang.id)} className="text-red-500">
              Hapus
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      );
    },
  },
];

export default function MasterBarangPage() {
  const [data, setData] = useState<Barang[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isFormModalOpen, setFormModalOpen] = useState(false);
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);
  const [selectedBarang, setSelectedBarang] = useState<Barang | null>(null);
  const { toast } = useToast();

  const [satuanList, setSatuanList] = useState<{ id: string, nama: string }[]>([]);
  const [jenisList, setJenisList] = useState<{ id: string, nama: string }[]>([]);

  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [barangRes, satuanRes, jenisRes] = await Promise.all([
        fetch('/api/master-data/barang'),
        fetch('/api/master-data/satuan'),
        fetch('/api/master-data/jenis')
      ]);

      if (!barangRes.ok || !satuanRes.ok || !jenisRes.ok) {
        throw new Error('Gagal memuat data master');
      }

      const barangResult = await barangRes.json();
      const satuanResult = await satuanRes.json();
      const jenisResult = await jenisRes.json();

      setData(barangResult.data || []);
      setSatuanList(satuanResult.data || []);
      setJenisList(jenisResult.data || []);

    } catch (error) {
      toast({
        title: "Error",
        description: "Gagal memuat data.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleSuccess = () => {
    fetchData();
    setFormModalOpen(false);
    setSelectedBarang(null);
  };
  
  const handleEdit = (barang: Barang) => {
    setSelectedBarang(barang);
    setFormModalOpen(true);
  };
  
  const handleDelete = async (id: string) => {
    if(!confirm("Apakah Anda yakin ingin menghapus barang ini?")) return;
    try {
        const response = await fetch(`/api/master-data/barang/${id}`, {
            method: 'DELETE',
        });
        if(!response.ok) throw new Error("Gagal menghapus barang.");
        toast({
            title: "Berhasil",
            description: "Barang berhasil dihapus.",
        });
        fetchData();
    } catch(error) {
        toast({
            title: "Error",
            description: (error as Error).message,
            variant: "destructive",
        });
    }
  };

  const handleImport = async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);

    setIsLoading(true);
    try {
      const response = await fetch('/api/master-data/barang/import', {
        method: 'POST',
        body: formData,
      });

      const result = await response.json();
      if (!response.ok) {
        let errorMessage = result.error || 'Gagal mengimpor file.';
        if (result.details && Array.isArray(result.details)) {
          // Add a newline for better formatting in the toast
          const details = result.details.join('\\n');
          errorMessage = `${errorMessage}:\\n${details}`;
        }
        throw new Error(errorMessage);
      }

      toast({
        title: "Import Berhasil",
        description: result.message,
        className: "whitespace-pre-line",
      });
      setIsImportModalOpen(false);
      fetchData();
    } catch (error) {
      toast({
        title: "Error",
        description: (error as Error).message,
        variant: "destructive",
        className: "whitespace-pre-line", // Allow newlines in toast
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleViewDetail = (barang: Barang) => {
    setSelectedBarang(barang);
    setIsDetailModalOpen(true);
  };

  const columns = getColumns({ onEdit: handleEdit, onDelete: handleDelete, onViewDetail: handleViewDetail });

  return (
    <div className="w-full px-6 py-10">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Master Barang</h1>
        <div className="flex gap-2">
            <Button onClick={() => setIsImportModalOpen(true)} variant="outline">
                <Upload className="mr-2 h-4 w-4" />
                Import
            </Button>
            <Button onClick={() => { setSelectedBarang(null); setFormModalOpen(true); }}>
                <Plus className="mr-2 h-4 w-4" />
                Tambah Barang
            </Button>
        </div>
      </div>
      <div className="relative z-0">
        <DataTable
          columns={columns}
          data={data}
          isLoading={isLoading}
          searchKey="nama"
        />
      </div>
      <BarangFormModal
        isOpen={isFormModalOpen}
        onClose={() => setFormModalOpen(false)}
        onSuccess={handleSuccess}
        barangData={selectedBarang}
        satuanList={satuanList}
        jenisList={jenisList}
        onDataMasterChange={fetchData}
      />
       <BarangImportModal
        isOpen={isImportModalOpen}
        onClose={() => setIsImportModalOpen(false)}
        onImport={handleImport}
      />
      <BarangDetailModal
        isOpen={isDetailModalOpen}
        onClose={() => setIsDetailModalOpen(false)}
        barang={selectedBarang}
      />
    </div>
  );
}

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
import { PlusCircle, Search, Eye } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import { useDebounce } from "@/hooks/use-debounce";
import { useRouter } from "next/navigation";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface Gudang {
  id: string;
  kode: string;
  nama: string;
  kategori: string;
  alamat: string;
  jumlahBarang: number;
  jumlahStok: number;
  createdAt: string;
  updatedAt: string;
}

const KATEGORI_OPTIONS = [
  { value: "Bahan Baku", label: "Bahan Baku" },
  { value: "Barang Setengah Jadi", label: "Barang Setengah Jadi" },
  { value: "Barang Jadi", label: "Barang Jadi" },
];

export default function GudangPage() {
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [gudangs, setGudangs] = useState<Gudang[]>([]);
  const [form, setForm] = useState({
    kode: "",
    nama: "",
    kategori: "",
    alamat: "",
  });
  const debouncedSearch = useDebounce(searchQuery, 300);

  // Fetch gudangs from API
  useEffect(() => {
    const fetchGudangs = async () => {
      try {
        const url = debouncedSearch
          ? `/api/master/gudang/search?q=${encodeURIComponent(debouncedSearch)}`
          : "/api/master/gudang";
        const res = await fetch(url);
        if (!res.ok) throw new Error("Failed to fetch gudangs");
        const result = await res.json();
        setGudangs(result.data || []);
      } catch (error) {
        console.error("Error fetching gudangs:", error);
        toast.error("Gagal memuat data gudang");
      }
    };
    fetchGudangs();
  }, [debouncedSearch]);

  // Generate kode gudang
  const generateKodeGudang = async () => {
    try {
      const res = await fetch("/api/master/gudang/generate-kode");
      if (!res.ok) throw new Error("Failed to generate kode");
      const { kode } = await res.json();
      setForm(prev => ({ ...prev, kode }));
    } catch (error) {
      console.error("Error generating kode:", error);
      toast.error("Gagal generate kode gudang");
    }
  };

  // Generate kode when modal opens
  useEffect(() => {
    if (open) {
      generateKodeGudang();
    }
  }, [open]);

  const onChangeForm = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const onKategoriChange = (value: string) => {
    setForm(prev => ({ ...prev, kategori: value }));
  };

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const res = await fetch("/api/master/gudang", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!res.ok) {
        const errorData = await res.text();
        throw new Error(errorData || "Gagal menambah gudang");
      }
      const newGudang = await res.json();
      setGudangs((prev) => [newGudang, ...prev]);
      setOpen(false);
      setForm({ kode: "", nama: "", kategori: "", alamat: "" });
      toast.success("Gudang berhasil ditambahkan");
    } catch (error) {
      console.error("Error adding gudang:", error);
      toast.error(error instanceof Error ? error.message : "Gagal menambah gudang");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Data Gudang</h1>
        <Button onClick={() => setOpen(true)}>
          <PlusCircle className="w-4 h-4 mr-2" />
          Tambah Gudang
        </Button>
      </div>

      <div className="flex items-center space-x-2 mb-4">
        <div className="relative w-64">
          <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Cari gudang..."
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
              <TableHead>Kode</TableHead>
              <TableHead>Nama</TableHead>
              <TableHead>Kategori</TableHead>
              <TableHead>Alamat</TableHead>
              <TableHead>Jumlah Barang</TableHead>
              <TableHead>Jumlah Stok</TableHead>
              <TableHead className="text-center">Aksi</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {gudangs.map((gudang) => (
              <TableRow key={gudang.id}>
                <TableCell>{gudang.kode}</TableCell>
                <TableCell>{gudang.nama}</TableCell>
                <TableCell>{gudang.kategori}</TableCell>
                <TableCell>{gudang.alamat}</TableCell>
                <TableCell>{gudang.jumlahBarang}</TableCell>
                <TableCell>{gudang.jumlahStok}</TableCell>
                <TableCell className="text-center">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-emerald-600 hover:text-emerald-700 hover:bg-emerald-50 mx-auto"
                    onClick={() => router.push(`/master/gudang/${gudang.id}`)}
                  >
                    <Eye className="w-4 h-4 mr-2" />
                    Lihat Gudang
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Tambah Gudang Baru</DialogTitle>
          </DialogHeader>
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="space-y-2">
              <Label htmlFor="kode">Kode Gudang</Label>
              <Input
                id="kode"
                name="kode"
                value={form.kode}
                readOnly
                className="bg-gray-100"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="nama">Nama Gudang</Label>
              <Input
                id="nama"
                name="nama"
                value={form.nama}
                onChange={onChangeForm}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="kategori">Kategori</Label>
              <Select
                value={form.kategori}
                onValueChange={onKategoriChange}
                required
              >
                <SelectTrigger>
                  <SelectValue placeholder="Pilih kategori" />
                </SelectTrigger>
                <SelectContent>
                  {KATEGORI_OPTIONS.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="alamat">Alamat</Label>
              <Textarea
                id="alamat"
                name="alamat"
                value={form.alamat}
                onChange={onChangeForm}
                required
              />
            </div>
            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? "Menyimpan..." : "Simpan"}
            </Button>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
} 
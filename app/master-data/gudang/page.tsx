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
import { PlusCircle, Search, Trash2 } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import { useDebounce } from "@/hooks/use-debounce";

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

export default function GudangPage() {
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
          ? `/api/master-data/gudang/search?q=${encodeURIComponent(debouncedSearch)}`
          : "/api/master-data/gudang";
        const res = await fetch(url);
        if (!res.ok) throw new Error("Failed to fetch gudangs");
        const data = await res.json();
        setGudangs(data);
      } catch (error) {
        console.error("Error fetching gudangs:", error);
        toast.error("Gagal memuat data gudang");
      }
    };
    fetchGudangs();
  }, [debouncedSearch]);

  const onChangeForm = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const res = await fetch("/api/master-data/gudang", {
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

  const onDelete = async (id: string) => {
    try {
      const response = await fetch(`/api/master-data/gudang?id=${id}`, {
        method: "DELETE",
      });
      if (!response.ok) throw new Error("Failed to delete gudang");
      setGudangs((prev) => prev.filter((g) => g.id !== id));
      toast.success("Gudang berhasil dihapus");
    } catch (error) {
      toast.error("Gagal menghapus gudang");
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
              <TableHead className="text-right">Aksi</TableHead>
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
                <TableCell className="text-right">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => onDelete(gudang.id)}
                    className="text-red-500 hover:text-red-700"
                  >
                    <Trash2 className="h-4 w-4" />
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
                onChange={onChangeForm}
                required
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
              <Input
                id="kategori"
                name="kategori"
                value={form.kategori}
                onChange={onChangeForm}
                required
              />
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
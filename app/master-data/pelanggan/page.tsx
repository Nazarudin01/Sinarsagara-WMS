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

interface Pelanggan {
  id: string;
  nama: string;
  alamat: string;
  telepon: string;
  email: string;
  createdAt: string;
}

export default function PelangganPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [pelanggans, setPelanggans] = useState<Pelanggan[]>([]);
  const [form, setForm] = useState({
    nama: "",
    alamat: "",
    telepon: "",
    email: "",
  });
  const debouncedSearch = useDebounce(searchQuery, 300);

  // Fetch pelanggans from API
  useEffect(() => {
    const fetchPelanggans = async () => {
      try {
        const url = debouncedSearch
          ? `/api/master-data/pelanggan/search?q=${encodeURIComponent(debouncedSearch)}`
          : "/api/master-data/pelanggan";
        const res = await fetch(url);
        if (!res.ok) throw new Error("Failed to fetch pelanggans");
        const result = await res.json();
        setPelanggans(result.data || []);
      } catch (error) {
        console.error("Error fetching pelanggans:", error);
        toast.error("Gagal memuat data pelanggan");
      }
    };
    fetchPelanggans();
  }, [debouncedSearch]);

  const onChangeForm = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const res = await fetch("/api/master-data/pelanggan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!res.ok) {
        const errorData = await res.text();
        throw new Error(errorData || "Gagal menambah pelanggan");
      }
      const newPelanggan = await res.json();
      setPelanggans((prev) => [newPelanggan.data, ...prev]);
      setOpen(false);
      setForm({ nama: "", alamat: "", telepon: "", email: "" });
      toast.success("Pelanggan berhasil ditambahkan");
    } catch (error) {
      console.error("Error adding pelanggan:", error);
      toast.error(error instanceof Error ? error.message : "Gagal menambah pelanggan");
    } finally {
      setIsLoading(false);
    }
  };

  const onDelete = async (id: string) => {
    try {
      const response = await fetch(`/api/master-data/pelanggan?id=${id}`, {
        method: "DELETE",
      });
      if (!response.ok) throw new Error("Failed to delete pelanggan");
      setPelanggans((prev) => prev.filter((p) => p.id !== id));
      toast.success("Pelanggan berhasil dihapus");
    } catch (error) {
      toast.error("Gagal menghapus pelanggan");
    }
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Data Pelanggan</h1>
        <Button onClick={() => setOpen(true)}>
          <PlusCircle className="w-4 h-4 mr-2" />
          Tambah Pelanggan
        </Button>
      </div>

      <div className="flex items-center space-x-2 mb-4">
        <div className="relative w-64">
          <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Cari pelanggan..."
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
              <TableHead>Nama</TableHead>
              <TableHead>Alamat</TableHead>
              <TableHead>Telepon</TableHead>
              <TableHead>Email</TableHead>
              <TableHead className="text-right">Aksi</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {pelanggans.map((pelanggan) => (
              <TableRow key={pelanggan.id}>
                <TableCell>{pelanggan.nama}</TableCell>
                <TableCell>{pelanggan.alamat}</TableCell>
                <TableCell>{pelanggan.telepon}</TableCell>
                <TableCell>{pelanggan.email}</TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => onDelete(pelanggan.id)}
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
            <DialogTitle>Tambah Pelanggan Baru</DialogTitle>
          </DialogHeader>
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="space-y-2">
              <Label htmlFor="nama">Nama Pelanggan</Label>
              <Input
                id="nama"
                name="nama"
                value={form.nama}
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
            <div className="space-y-2">
              <Label htmlFor="telepon">Telepon</Label>
              <Input
                id="telepon"
                name="telepon"
                value={form.telepon}
                onChange={onChangeForm}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                name="email"
                type="email"
                value={form.email}
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
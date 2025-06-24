"use client";

import { useState, useEffect, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PlusCircle, Upload, Eye, Trash2 } from "lucide-react";
import Link from "next/link";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { toast } from "sonner";

// Dummy data untuk contoh
const dummyData = [
  // Contoh data, bisa diubah dengan fetch API nanti
  // {
  //   id: "1",
  //   nomor: "OP-001",
  //   tanggal: "2024-06-25",
  //   gudang: "Gudang Utama",
  //   jumlahStok: 100,
  //   jumlahStokAktual: 98,
  //   penanggungJawab: "Budi",
  // },
];

export default function StokOpnamePage() {
  const [data, setData] = useState([]);
  const [deleteId, setDeleteId] = useState<string|null>(null);
  const [loading, setLoading] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [importGudang, setImportGudang] = useState<string | undefined>(undefined);
  const [importFormat, setImportFormat] = useState<'excel'|'csv'>('excel');
  const [gudangList, setGudangList] = useState<any[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchData = () => {
    fetch("/api/opname")
      .then((res) => res.json())
      .then((res) => setData(res.data || []));
  };

  useEffect(() => {
    fetchData();
    fetch("/api/master/gudang").then(res => res.json()).then(res => setGudangList(res.data || []));
  }, []);

  const handleDelete = async () => {
    if (!deleteId) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/opname?id=${deleteId}`, { method: "DELETE" });
      if (!res.ok) throw new Error(await res.text());
      toast.success("Data opname berhasil dihapus dan stok barang terupdate!");
      setDeleteId(null);
      fetchData();
    } catch (error) {
      toast.error("Gagal menghapus opname");
    } finally {
      setLoading(false);
    }
  };

  const handleImport = async () => {
    if (!importGudang || !fileInputRef.current?.files?.[0]) {
      toast.error("Pilih gudang dan file terlebih dahulu");
      return;
    }
    const formData = new FormData();
    formData.append("file", fileInputRef.current.files[0]);
    setLoading(true);
    try {
      const res = await fetch("/api/opname/import", {
        method: "POST",
        body: formData,
      });
      if (!res.ok) throw new Error(await res.text());
      toast.success("Import opname berhasil!");
      setShowImport(false);
      fetchData();
    } catch (error) {
      toast.error("Gagal import opname");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Stok Opname</h1>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => setShowImport(true)}>
            <Upload className="w-4 h-4 mr-2" />
            Import
          </Button>
          <Button asChild>
            <Link href="/opname/buat">
              <PlusCircle className="w-4 h-4 mr-2" />
              Buat Opname
            </Link>
          </Button>
        </div>
      </div>
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>No Opname</TableHead>
              <TableHead>Tanggal</TableHead>
              <TableHead>Gudang</TableHead>
              <TableHead>Jumlah Stok</TableHead>
              <TableHead>Jumlah Stok Aktual</TableHead>
              <TableHead>Penanggung Jawab</TableHead>
              <TableHead className="text-right">Aksi</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-muted-foreground">
                  Belum ada data opname
                </TableCell>
              </TableRow>
            ) : (
              data.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>{row.nomor}</TableCell>
                  <TableCell>{row.tanggal}</TableCell>
                  <TableCell>{row.gudang}</TableCell>
                  <TableCell>{row.jumlahStok}</TableCell>
                  <TableCell>{row.jumlahStokAktual}</TableCell>
                  <TableCell>{row.penanggungJawab}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon">
                      <Eye className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon" onClick={() => setDeleteId(row.id)} className="text-red-500">
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      <Dialog open={!!deleteId} onOpenChange={v => !v && setDeleteId(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Konfirmasi Hapus Opname</DialogTitle>
          </DialogHeader>
          <div className="mb-4">
            Apakah kamu yakin ingin menghapus hasil opname ini? Data stok barang akan dikembalikan ke kondisi sebelum opname.
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteId(null)} disabled={loading}>
              Batal
            </Button>
            <Button onClick={handleDelete} disabled={loading} className="bg-red-600 text-white">
              Ya, Hapus
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={showImport} onOpenChange={setShowImport}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Import Stok Opname</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <label className="block mb-2 font-semibold">Pilih Gudang</label>
              <select
                className="w-full border rounded px-2 py-1"
                value={importGudang || ''}
                onChange={e => setImportGudang(e.target.value)}
              >
                <option value="">Pilih Gudang</option>
                {gudangList.map((g: any) => (
                  <option key={g.id} value={g.id}>{g.nama}</option>
                ))}
              </select>
            </div>
            {importGudang && (
              <div className="flex items-center gap-2">
                <span>Download template:</span>
                <Button size="sm" variant={importFormat==='excel'?'default':'outline'} onClick={()=>setImportFormat('excel')}>
                  Excel
                </Button>
                <Button size="sm" variant={importFormat==='csv'?'default':'outline'} onClick={()=>setImportFormat('csv')}>
                  CSV
                </Button>
                <Button size="sm" onClick={()=>window.open(`/api/opname/template?gudangId=${importGudang}&format=${importFormat}`)}>
                  Download
                </Button>
              </div>
            )}
            <div>
              <label className="block mb-2 font-semibold">Pilih File Opname</label>
              <input ref={fileInputRef} type="file" accept=".xlsx,.xls,.csv" className="w-full" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={()=>setShowImport(false)} disabled={loading}>
              Batal
            </Button>
            <Button onClick={handleImport} disabled={loading}>
              Import Opname
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
} 
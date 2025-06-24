"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { toast } from "sonner";
import { DatePicker } from "@/components/ui/date-picker";
import { useRouter } from "next/navigation";
import { PlusCircle, Upload, Eye, Image as ImageIcon } from "lucide-react";

// Dummy data gudang dan barang
const gudangList = [
  { id: "g1", nama: "Gudang Utama" },
  { id: "g2", nama: "Gudang Cabang" },
];
const barangList = [
  {
    id: "b1",
    gambar: "https://via.placeholder.com/40",
    kodeRak: "R01",
    sku: "SKU-001",
    nama: "Barang A",
    stok: 100,
    satuan: "pcs",
  },
  {
    id: "b2",
    gambar: "https://via.placeholder.com/40",
    kodeRak: "R02",
    sku: "SKU-002",
    nama: "Barang B",
    stok: 50,
    satuan: "pcs",
  },
];

function generateNomorOpname(lastNomor: string | null) {
  const now = new Date();
  const mm = String(now.getMonth() + 1).padStart(2, "0");
  const yy = String(now.getFullYear()).slice(-2);
  let urut = 1;
  if (lastNomor && lastNomor.startsWith(`OPN-${mm}${yy}-`)) {
    const last = parseInt(lastNomor.split("-")[2], 10);
    urut = last + 1;
  }
  return `OPN-${mm}${yy}-${String(urut).padStart(3, "0")}`;
}

export default function BuatOpnamePage() {
  const [gudangId, setGudangId] = useState<string | null>(null);
  const [gudangList, setGudangList] = useState<any[]>([]);
  const [data, setData] = useState<any[]>([]);
  const [tanggal, setTanggal] = useState<Date>(new Date());
  const [penanggungJawab, setPenanggungJawab] = useState("");
  const [nomorOpname, setNomorOpname] = useState<string>("");
  const [showModal, setShowModal] = useState(false);
  const [loadingBarang, setLoadingBarang] = useState(false);
  const router = useRouter();

  // Fetch gudang
  useEffect(() => {
    fetch("/api/master/gudang")
      .then((res) => res.json())
      .then((res) => setGudangList(res.data || []));
  }, []);

  // Fetch barang di gudang
  useEffect(() => {
    if (!gudangId) return;
    setLoadingBarang(true);
    fetch(`/api/stok-gudang/${gudangId}`)
      .then((res) => res.json())
      .then((res) => {
        setData(
          (res.data || []).map((b: any) => ({ ...b, stokAktual: b.stok, selisih: 0 }))
        );
        setLoadingBarang(false);
      });
  }, [gudangId]);

  // Generate nomor opname dari API
  useEffect(() => {
    fetch("/api/opname/generate-nomor")
      .then((res) => res.json())
      .then((res) => setNomorOpname(res.nomor || ""));
  }, []);

  // Update stok aktual dan selisih
  const handleStokAktualChange = (id: string, value: string) => {
    setData((prev) =>
      prev.map((row) =>
        row.id === id
          ? {
              ...row,
              stokAktual: Number(value),
              selisih: Number(value) - row.stok,
            }
          : row
      )
    );
  };

  const handleSimpan = () => {
    if (!penanggungJawab) {
      toast.error("Penanggung Jawab wajib diisi");
      return;
    }
    setShowModal(true);
  };

  const handleKonfirmasi = async () => {
    setShowModal(false);
    try {
      const res = await fetch("/api/opname", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          nomor: nomorOpname,
          tanggal,
          gudangId,
          penanggungJawab,
          items: data.map((row) => ({
            id: row.id,
            barangId: row.barangId,
            stok: row.stok,
            stokAktual: row.stokAktual,
            selisih: row.selisih,
            satuan: row.satuan,
          })),
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      toast.success("Opname berhasil disimpan dan stok gudang terupdate!");
      router.push("/opname");
    } catch (error) {
      toast.error("Gagal menyimpan opname");
    }
  };

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">Buat Stok Opname</h1>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div>
          <label className="block mb-2 font-semibold">No Opname</label>
          <Input value={nomorOpname} readOnly />
        </div>
        <div>
          <label className="block mb-2 font-semibold">Tanggal</label>
          <DatePicker selected={tanggal} onSelect={setTanggal} />
        </div>
        <div>
          <label className="block mb-2 font-semibold">Penanggung Jawab</label>
          <Input
            value={penanggungJawab}
            onChange={(e) => setPenanggungJawab(e.target.value)}
            required
            placeholder="Nama Penanggung Jawab"
          />
        </div>
      </div>
      <div className="mb-6 max-w-xs">
        <label className="block mb-2 font-semibold">Pilih Gudang</label>
        <Select onValueChange={setGudangId} value={gudangId || undefined}>
          <SelectTrigger>
            <SelectValue placeholder="Pilih Gudang" />
          </SelectTrigger>
          <SelectContent>
            {gudangList.map((g) => (
              <SelectItem key={g.id} value={g.id}>{g.nama}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {gudangId && (
        <div className="border rounded-lg">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Gambar</TableHead>
                <TableHead>Kode Rak</TableHead>
                <TableHead>SKU</TableHead>
                <TableHead>Nama Barang</TableHead>
                <TableHead>Stok</TableHead>
                <TableHead>Stok Aktual</TableHead>
                <TableHead>Selisih</TableHead>
                <TableHead>Satuan</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loadingBarang ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center">Loading...</TableCell>
                </TableRow>
              ) : data.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center text-muted-foreground">
                    Tidak ada barang di gudang ini
                  </TableCell>
                </TableRow>
              ) : (
                data.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell>
                      {row.gambar ? (
                        <img src={row.gambar} alt={row.nama} className="w-10 h-10 object-cover rounded" />
                      ) : (
                        <ImageIcon className="w-8 h-8 text-gray-400 mx-auto" />
                      )}
                    </TableCell>
                    <TableCell>{row.kodeRak}</TableCell>
                    <TableCell>{row.sku}</TableCell>
                    <TableCell>{row.nama}</TableCell>
                    <TableCell>{row.stok}</TableCell>
                    <TableCell>
                      <Input
                        type="number"
                        min={0}
                        value={row.stokAktual}
                        onChange={(e) => handleStokAktualChange(row.id, e.target.value)}
                        className="w-24"
                      />
                    </TableCell>
                    <TableCell>{row.selisih}</TableCell>
                    <TableCell>{row.satuan}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          <div className="flex justify-end p-4">
            <Button onClick={handleSimpan}>Simpan Opname</Button>
          </div>
        </div>
      )}
      <Dialog open={showModal} onOpenChange={setShowModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Konfirmasi Simpan Opname</DialogTitle>
          </DialogHeader>
          <div className="mb-4">
            Apakah kamu yakin ingin menyimpan hasil opname dan akan merubah hasil akhir gudang?
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowModal(false)}>
              Batal
            </Button>
            <Button onClick={handleKonfirmasi}>
              Ya, Simpan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
} 
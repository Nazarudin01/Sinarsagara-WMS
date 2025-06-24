"use client";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Download, Calendar, Warehouse } from "lucide-react";

const dummyGudang = [
  { id: "g1", nama: "Gudang Utama" },
  { id: "g2", nama: "Gudang Cabang" },
];

const dummyData = [
  {
    gambar: "https://via.placeholder.com/40",
    rak: "A1",
    sku: "SKU001",
    nama: "Barang A",
    satuan: "pcs",
    jenis: "Elektronik",
    stokAwal: 100,
    masuk: 20,
    keluar: 10,
    opname: 2,
    stokAkhir: 108,
  },
  {
    gambar: "https://via.placeholder.com/40",
    rak: "B2",
    sku: "SKU002",
    nama: "Barang B",
    satuan: "box",
    jenis: "ATK",
    stokAwal: 50,
    masuk: 5,
    keluar: 3,
    opname: 0,
    stokAkhir: 52,
  },
];

export default function LaporanStokPage() {
  const [gudang, setGudang] = useState("");
  const [gudangList, setGudangList] = useState<any[]>([]);
  const [rentang, setRentang] = useState("harian");
  const [tanggal, setTanggal] = useState("");
  const [minggu, setMinggu] = useState("");
  const [bulan, setBulan] = useState("");
  const [showExport, setShowExport] = useState(false);
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  // Fetch daftar gudang dari API
  useEffect(() => {
    fetch("/api/master/gudang")
      .then(res => res.json())
      .then(res => setGudangList(res.data || []));
  }, []);

  // Fetch data dari API
  useEffect(() => {
    if (!gudang) return setData([]);
    setLoading(true);
    const params = new URLSearchParams();
    params.set("gudangId", gudang);
    params.set("rentang", rentang);
    if (rentang === "harian" && tanggal) params.set("tanggal", tanggal);
    if (rentang === "mingguan" && minggu) params.set("minggu", minggu);
    if (rentang === "bulanan" && bulan) params.set("bulan", bulan);
    fetch(`/api/laporan/stok?${params.toString()}`)
      .then(res => res.json())
      .then(res => setData(res.data || []))
      .finally(() => setLoading(false));
  }, [gudang, rentang, tanggal, minggu, bulan]);

  // Export handler
  const handleExport = async (type: 'excel' | 'csv') => {
    if (!gudang) return;
    const params = new URLSearchParams();
    params.set("gudangId", gudang);
    params.set("rentang", rentang);
    if (rentang === "harian" && tanggal) params.set("tanggal", tanggal);
    if (rentang === "mingguan" && minggu) params.set("minggu", minggu);
    if (rentang === "bulanan" && bulan) params.set("bulan", bulan);
    params.set("type", type);
    const res = await fetch(`/api/laporan/stok/export?${params.toString()}`);
    if (!res.ok) return alert("Gagal export");
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `laporan-stok.${type === 'excel' ? 'xlsx' : 'csv'}`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    setShowExport(false);
  };

  return (
    <div className="p-6 max-w-full">
      <h1 className="text-2xl font-bold mb-6">Laporan Stok</h1>
      <div className="flex flex-wrap gap-4 mb-6 items-end">
        <div>
          <label className="block mb-1 font-semibold">Pilih Gudang</label>
          <select
            className="border rounded px-2 py-1 min-w-[180px]"
            value={gudang}
            onChange={e => setGudang(e.target.value)}
          >
            <option value="">Pilih Gudang</option>
            {gudangList.map(g => (
              <option key={g.id} value={g.id}>{g.nama}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block mb-1 font-semibold">Rentang Waktu</label>
          <select
            className="border rounded px-2 py-1 min-w-[120px]"
            value={rentang}
            onChange={e => setRentang(e.target.value)}
          >
            <option value="harian">Harian</option>
            <option value="mingguan">Mingguan</option>
            <option value="bulanan">Bulanan</option>
          </select>
        </div>
        {rentang === "harian" && (
          <div>
            <label className="block mb-1 font-semibold">Tanggal</label>
            <input type="date" className="border rounded px-2 py-1" value={tanggal} onChange={e => setTanggal(e.target.value)} />
          </div>
        )}
        {rentang === "mingguan" && (
          <div>
            <label className="block mb-1 font-semibold">Minggu (yyyy-Wxx)</label>
            <input type="week" className="border rounded px-2 py-1" value={minggu} onChange={e => setMinggu(e.target.value)} />
          </div>
        )}
        {rentang === "bulanan" && (
          <div>
            <label className="block mb-1 font-semibold">Bulan</label>
            <input type="month" className="border rounded px-2 py-1" value={bulan} onChange={e => setBulan(e.target.value)} />
          </div>
        )}
        <div className="relative">
          <Button type="button" onClick={() => setShowExport(v => !v)}>
            <Download className="w-4 h-4 mr-2" />
            Export Laporan
          </Button>
          {showExport && (
            <div className="absolute z-10 bg-white border rounded shadow mt-2 min-w-[150px]">
              <button className="block w-full text-left px-4 py-2 hover:bg-gray-100" onClick={() => handleExport('excel')}>Download Excel</button>
              <button className="block w-full text-left px-4 py-2 hover:bg-gray-100" onClick={() => handleExport('csv')}>Download CSV</button>
            </div>
          )}
        </div>
      </div>
      <div className="overflow-x-auto border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>No</TableHead>
              <TableHead>Gambar</TableHead>
              <TableHead>Rak</TableHead>
              <TableHead>SKU</TableHead>
              <TableHead>Nama Barang</TableHead>
              <TableHead>Satuan</TableHead>
              <TableHead>Jenis</TableHead>
              <TableHead>Stok Awal</TableHead>
              <TableHead>Masuk</TableHead>
              <TableHead>Keluar</TableHead>
              <TableHead>Opname</TableHead>
              <TableHead>Stok Akhir</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={12} className="text-center">Loading...</TableCell>
              </TableRow>
            ) : data.length === 0 ? (
              <TableRow>
                <TableCell colSpan={12} className="text-center">Tidak ada data</TableCell>
              </TableRow>
            ) : (
              data.map((row, i) => (
                <TableRow key={row.sku}>
                  <TableCell>{i + 1}</TableCell>
                  <TableCell><img src={row.gambar} alt={row.nama} className="w-10 h-10 object-cover rounded" /></TableCell>
                  <TableCell>{row.rak}</TableCell>
                  <TableCell>{row.sku}</TableCell>
                  <TableCell>{row.nama}</TableCell>
                  <TableCell>{row.satuan}</TableCell>
                  <TableCell>{row.jenis}</TableCell>
                  <TableCell>{row.stokAwal}</TableCell>
                  <TableCell>{row.masuk}</TableCell>
                  <TableCell>{row.keluar}</TableCell>
                  <TableCell>
                    {row.opname === 0 ? (
                      <span className="text-gray-500">0</span>
                    ) : row.opname > 0 ? (
                      <span className="text-green-600 font-bold">+{row.opname}</span>
                    ) : (
                      <span className="text-red-600 font-bold">{row.opname}</span>
                    )}
                  </TableCell>
                  <TableCell>{row.stokAkhir}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
} 
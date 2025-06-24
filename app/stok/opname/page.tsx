"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PlusCircle, Upload, Eye } from "lucide-react";

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
  const [data, setData] = useState(dummyData);

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Stok Opname</h1>
        <div className="flex gap-2">
          <Button variant="outline">
            <Upload className="w-4 h-4 mr-2" />
            Import
          </Button>
          <Button>
            <PlusCircle className="w-4 h-4 mr-2" />
            Buat Opname
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
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
} 
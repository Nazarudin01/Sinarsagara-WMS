"use client";

import { useState } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { format } from 'date-fns';
import { id } from 'date-fns/locale';

interface TransaksiMasuk {
  id: string;
  nomor: string;
  tanggal: string;
  supplier: string;
  gudang: string;
  status: "pending" | "approved" | "rejected";
  total: number;
  created_at: string;
  updated_at: string;
}

interface TransaksiMasukTableProps {
  data: TransaksiMasuk[];
}

export function TransaksiMasukTable({ data }: TransaksiMasukTableProps) {
  const [searchQuery, setSearchQuery] = useState('');

  const filteredData = data.filter((item) => {
    const searchLower = searchQuery.toLowerCase();
    return (
      item.nomor.toLowerCase().includes(searchLower) ||
      item.supplier.toLowerCase().includes(searchLower) ||
      item.gudang.toLowerCase().includes(searchLower)
    );
  });

  const formatDate = (dateString: string) => {
    return format(new Date(dateString), 'dd MMMM yyyy', { locale: id });
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('id-ID', {
      style: 'currency',
      currency: 'IDR',
    }).format(amount);
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'approved':
        return <Badge className="bg-green-500">Disetujui</Badge>;
      case 'rejected':
        return <Badge variant="destructive">Ditolak</Badge>;
      default:
        return <Badge variant="secondary">Menunggu</Badge>;
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <Input
          placeholder="Cari nomor, supplier, atau gudang..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="max-w-sm"
        />
        <Button>Tambah Transaksi</Button>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Nomor</TableHead>
              <TableHead>Tanggal</TableHead>
              <TableHead>Supplier</TableHead>
              <TableHead>Gudang</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Total</TableHead>
              <TableHead className="text-right">Aksi</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredData.length > 0 ? (
              filteredData.map((item) => (
                <TableRow key={item.id}>
                  <TableCell className="font-medium">{item.nomor}</TableCell>
                  <TableCell>{formatDate(item.tanggal)}</TableCell>
                  <TableCell>{item.supplier}</TableCell>
                  <TableCell>{item.gudang}</TableCell>
                  <TableCell>{getStatusBadge(item.status)}</TableCell>
                  <TableCell className="text-right">{formatCurrency(item.total)}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm">
                      Detail
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={7} className="h-24 text-center">
                  Tidak ada data.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
} 
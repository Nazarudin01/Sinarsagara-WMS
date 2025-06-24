import { NextRequest, NextResponse } from 'next/server';
import * as XLSX from 'xlsx';

// Definisikan header untuk template
const headers = [
  "tanggal",
  "pemasok_nama",
  "kategori_barang",
  "gudang_nama",
  "rak_kode",
  "sku_or_nama_barang",
  "jumlah"
];

// Contoh data untuk baris pertama (opsional, untuk memberikan contoh format)
const exampleData = [
    {
        tanggal: "2024-12-31",
        pemasok_nama: "Nama Pemasok Anda",
        kategori_barang: "Kategori A",
        gudang_nama: "Nama Gudang Anda",
        rak_kode: "A1-01",
        sku_or_nama_barang: "SKU-001",
        jumlah: 10
    },
    {
        tanggal: "2024-12-31",
        pemasok_nama: "Nama Pemasok Anda",
        kategori_barang: "Kategori B",
        gudang_nama: "Nama Gudang Anda",
        rak_kode: "A1-02",
        sku_or_nama_barang: "Nama Barang Contoh B",
        jumlah: 5
    },
    {
        tanggal: "2025-01-01",
        pemasok_nama: "Nama Pemasok Lain",
        kategori_barang: "Kategori C",
        gudang_nama: "Nama Gudang Lain",
        rak_kode: "B2-05",
        sku_or_nama_barang: "SKU-003",
        jumlah: 20
    }
];

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const type = searchParams.get('type') || 'excel'; // default to excel

  try {
    const ws = XLSX.utils.json_to_sheet(exampleData, { header: headers });
    
    // Set lebar kolom agar lebih mudah dibaca
    ws['!cols'] = headers.map(h => ({ wch: h.length + 10 }));

    if (type === 'csv') {
      const csv = XLSX.utils.sheet_to_csv(ws);
      return new NextResponse(csv, {
        status: 200,
        headers: {
          'Content-Disposition': `attachment; filename="template_stok_masuk.csv"`,
          'Content-Type': 'text/csv',
        },
      });
    }

    // Default to Excel
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Template Stok Masuk');
    const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    return new NextResponse(buffer, {
      status: 200,
      headers: {
        'Content-Disposition': `attachment; filename="template_stok_masuk.xlsx"`,
        'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      },
    });

  } catch (error) {
    console.error("Error generating template:", error);
    return NextResponse.json(
      { error: 'Gagal membuat file template' },
      { status: 500 }
    );
  }
} 
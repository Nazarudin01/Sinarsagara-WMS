import { NextRequest, NextResponse } from 'next/server';
import * as XLSX from 'xlsx';

const headers = [
  "sku",
  "nama",
  "kategori",
  "satuan",
  "jenis",
  "hargaBeli"
];

const exampleData = [
    {
        sku: "SKU-BARANG-001",
        nama: "Nama Barang Contoh 1",
        kategori: "Kategori A",
        satuan: "PCS",
        jenis: "Jenis A",
        hargaBeli: 50000
    },
    {
        sku: "SKU-BARANG-002",
        nama: "Nama Barang Contoh 2",
        kategori: "Kategori B",
        satuan: "BOX",
        jenis: "Jenis B",
        hargaBeli: 125000
    },
];

export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const type = searchParams.get('type') || 'excel';

  try {
    const ws = XLSX.utils.json_to_sheet(exampleData, { header: headers });
    
    ws['!cols'] = headers.map(h => ({ wch: h.length + 10 }));

    if (type === 'csv') {
      const csv = XLSX.utils.sheet_to_csv(ws);
      return new NextResponse(csv, {
        status: 200,
        headers: {
          'Content-Disposition': `attachment; filename="template_barang.csv"`,
          'Content-Type': 'text/csv',
        },
      });
    }

    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Template Barang');
    const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

    return new NextResponse(buffer, {
      status: 200,
      headers: {
        'Content-Disposition': `attachment; filename="template_barang.xlsx"`,
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
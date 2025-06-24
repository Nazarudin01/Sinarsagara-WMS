import { NextRequest, NextResponse } from 'next/server';
import prisma from '@/lib/prisma';
import * as XLSX from 'xlsx';

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const gudangId = params.id;

    if (!gudangId) {
      return NextResponse.json(
        { error: 'ID Gudang tidak ditemukan' },
        { status: 400 }
      );
    }

    // Get gudang info
    const gudang = await prisma.gudang.findUnique({
      where: { id: gudangId },
    });

    if (!gudang) {
      return NextResponse.json(
        { error: 'Gudang tidak ditemukan' },
        { status: 404 }
      );
    }

    // Get all stok gudang for this warehouse
    const stokGudang = await prisma.stokGudang.findMany({
      where: { gudangId: gudangId },
      include: {
        barang: true,
        kodeRak: true,
      },
    });

    // Prepare data for Excel
    const dataToExport = stokGudang.map(item => ({
      'Kode Barang': item.barang.sku,
      'Nama Barang': item.barang.nama,
      Kategori: item.barang.kategori,
      'Kode Rak': item.kodeRak?.kode || 'N/A',
      Satuan: item.barang.satuan,
      Stok: item.stok,
    }));

    // Create a new workbook and a worksheet
    const workbook = XLSX.utils.book_new();
    const worksheet = XLSX.utils.json_to_sheet(dataToExport);

    // Append the worksheet to the workbook
    XLSX.utils.book_append_sheet(workbook, worksheet, `Barang di ${gudang.nama}`);

    // Generate a buffer
    const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });

    // Create filename
    const filename = `Data_Barang_Gudang_${gudang.nama.replace(/\s+/g, '_')}.xlsx`;

    // Return the file as a response
    return new NextResponse(buffer, {
      status: 200,
      headers: {
        'Content-Disposition': `attachment; filename="${filename}"`,
        'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      },
    });
  } catch (error) {
    console.error('Error exporting data:', error);
    return NextResponse.json(
      { error: 'Terjadi kesalahan saat mengekspor data' },
      { status: 500 }
    );
  }
} 
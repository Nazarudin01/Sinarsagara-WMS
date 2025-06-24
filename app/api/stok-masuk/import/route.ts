import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import prisma from "@/lib/prisma";
import * as XLSX from 'xlsx';
import { PrismaClient } from '@prisma/client';
import { format, parse } from 'date-fns';

// Function to parse date with multiple formats
function parseDateString(dateString: string): Date {
  const formats = [
    'yyyy-MM-dd',
    'dd-MM-yyyy',
    'MM/dd/yyyy',
    'dd/MM/yyyy',
    'd/M/yyyy'
  ];
  for (const fmt of formats) {
    try {
      const parsed = parse(dateString, fmt, new Date());
      if (!isNaN(parsed.getTime())) {
        return parsed;
      }
    } catch (e) {
      // ignore and try next format
    }
  }
  throw new Error(`Format tanggal tidak valid: ${dateString}`);
}

async function generateNextNomor(tx: Omit<PrismaClient, ".disconnect" | ".on" | ".connect" | ".use" | ".transaction">): Promise<string> {
  const today = new Date();
  const monthYear = format(today, 'MMyy'); // e.g., 0625 for June 2025
  const prefix = `SM-${monthYear}-`;

  const lastStokMasuk = await tx.stokMasuk.findFirst({
    where: { nomor: { startsWith: prefix } },
    orderBy: { nomor: 'desc' },
  });

  let nextId = 1;
  if (lastStokMasuk && lastStokMasuk.nomor) {
    const lastId = parseInt(lastStokMasuk.nomor.split('-')[2] || '0', 10);
    nextId = lastId + 1;
  }
  
  return `${prefix}${String(nextId).padStart(4, '0')}`;
}

export const config = {
  api: {
    bodyParser: false,
  },
};

export async function POST(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const formData = await request.formData();
    const file = formData.get('file') as File;

    if (!file) {
      return NextResponse.json({ error: "File tidak ditemukan." }, { status: 400 });
    }

    const buffer = Buffer.from(await file.arrayBuffer());
    const workbook = XLSX.read(buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const data: any[] = XLSX.utils.sheet_to_json(worksheet, { raw: false, dateNF: 'dd-MM-yyyy' });

    if (data.length === 0) {
      return NextResponse.json({ error: "File yang diupload kosong." }, { status: 400 });
    }
    
    const groupedByTransaction = data.reduce((acc, row) => {
      const tanggal = row.tanggal;
      const key = `${tanggal}-${row.pemasok_nama}-${row.gudang_nama}`;
      if (!acc[key]) {
        acc[key] = {
          tanggal: tanggal,
          pemasokNama: row.pemasok_nama,
          gudangNama: row.gudang_nama,
          items: [],
        };
      }
      acc[key].items.push({
        kategori: row.kategori_barang,
        identifier: row.sku_or_nama_barang,
        qty: Number(row.jumlah),
        rakKode: row.rak_kode,
      });
      return acc;
    }, {});
    
    let createdCount = 0;
    for (const group of Object.values(groupedByTransaction as any)) {
      await prisma.$transaction(async (tx) => {
        const { tanggal, pemasokNama, gudangNama, items } = group;

        const pemasok = await tx.pemasok.findFirst({ where: { nama: pemasokNama } });
        if (!pemasok) throw new Error(`Pemasok dengan nama "${pemasokNama}" tidak ditemukan.`);
        
        const gudang = await tx.gudang.findFirst({ where: { nama: gudangNama } });
        if (!gudang) throw new Error(`Gudang dengan nama "${gudangNama}" tidak ditemukan.`);
        
        const nextNomor = await generateNextNomor(tx);
        
        const parsedDate = parseDateString(tanggal);

        const stokMasuk = await tx.stokMasuk.create({
          data: {
            nomor: nextNomor,
            tanggal: parsedDate,
            pemasok: pemasok.id,
            gudang: gudang.id,
            status: "COMPLETED",
            total: 0,
          },
        });

        for (const item of items) {
          let barang = await tx.barang.findUnique({ where: { sku: item.identifier } });
          if (!barang) {
            barang = await tx.barang.findFirst({ where: { nama: item.identifier } });
          }
          if (!barang) throw new Error(`Barang dengan SKU atau Nama "${item.identifier}" tidak ditemukan.`);
          if (barang.kategori !== item.kategori) throw new Error(`Kategori "${item.kategori}" tidak cocok untuk barang "${barang.nama}".`);

          const rak = await tx.kodeRak.findUnique({ where: { kode: item.rakKode } });
          if (!rak) throw new Error(`Rak dengan kode "${item.rakKode}" tidak ditemukan.`);

          await tx.stokMasukItem.create({
            data: {
              stokMasukId: stokMasuk.id,
              sku: barang.sku,
              nama_barang: barang.nama,
              qty: item.qty,
              harga: 0,
              kodeRakId: rak.id,
            }
          });

          const existingStok = await tx.stokGudang.findFirst({
            where: { barangId: barang.id, gudangId: gudang.id, kodeRakId: rak.id },
          });

          if (existingStok) {
            await tx.stokGudang.update({
              where: { id: existingStok.id },
              data: { stok: { increment: item.qty } },
            });
          } else {
            await tx.stokGudang.create({
              data: {
                barangId: barang.id,
                gudangId: gudang.id,
                kodeRakId: rak.id,
                sku: barang.sku,
                nama: barang.nama,
                stok: item.qty,
              },
            });
          }
        }
      });
      createdCount++;
    }

    return NextResponse.json({
      message: `${createdCount} transaksi stok masuk berhasil diimpor.`,
    });

  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Terjadi kesalahan";
    console.error("Error importing file:", error);
    return NextResponse.json(
      { error: `Gagal mengimpor file: ${errorMessage}` },
      { status: 500 }
    );
  }
} 
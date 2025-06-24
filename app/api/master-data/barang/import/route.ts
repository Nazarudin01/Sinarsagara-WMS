import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import prisma from "@/lib/prisma";
import * as XLSX from 'xlsx';
import { z } from 'zod';

const barangSchema = z.object({
  sku: z.string().min(1, "SKU tidak boleh kosong"),
  nama: z.string().min(1, "Nama tidak boleh kosong"),
  kategori: z.string().min(1, "Kategori tidak boleh kosong"),
  satuan: z.string().min(1, "Satuan tidak boleh kosong"),
  jenis: z.string().min(1, "Jenis tidak boleh kosong"),
  hargaBeli: z.coerce.number().min(0, "Harga beli tidak boleh negatif"),
});

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
    const data: any[] = XLSX.utils.sheet_to_json(worksheet);

    if (data.length === 0) {
      return NextResponse.json({ error: "File yang diupload kosong." }, { status: 400 });
    }
    
    const validatedData = z.array(barangSchema).safeParse(data);
    
    if (!validatedData.success) {
      const errors = validatedData.error.issues.map(issue => `Baris ${Number(issue.path[0]) + 2}: ${issue.message} di kolom '${issue.path[1]}'`);
      return NextResponse.json({ error: "Data tidak valid", details: errors }, { status: 400 });
    }
    
    const skusInFile = validatedData.data.map(item => item.sku);
    const existingSkus = await prisma.barang.findMany({
        where: { sku: { in: skusInFile } }
    });

    if (existingSkus.length > 0) {
        const duplicateSkus = existingSkus.map(e => e.sku).join(', ');
        return NextResponse.json({ error: `SKU berikut sudah ada di database: ${duplicateSkus}` }, { status: 409 });
    }
    
    const result = await prisma.barang.createMany({
      data: validatedData.data,
      skipDuplicates: true,
    });

    return NextResponse.json({
      message: `${result.count} data barang berhasil diimpor.`,
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
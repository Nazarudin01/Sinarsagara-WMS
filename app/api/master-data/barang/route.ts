import { NextResponse, NextRequest } from "next/server";
import prisma from "@/lib/prisma";
import { writeFile } from 'fs/promises';
import path from 'path';
import { z } from 'zod';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const barang = await prisma.barang.findMany({
      orderBy: {
        nama: "asc",
      },
    });

    return NextResponse.json({
      data: barang,
    });
  } catch (error) {
    console.error("Error fetching barang:", error);
    return NextResponse.json(
      { error: "Gagal mengambil data barang" },
      { status: 500 }
    );
  }
}

const barangSchema = z.object({
  sku: z.string(),
  nama: z.string(),
  kategori: z.string(),
  satuan: z.string(),
  jenis: z.string(),
  hargaBeli: z.coerce.number(),
  gambar: z.string().optional(),
});

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    
    const data: Record<string, any> = {};
    for (const [key, value] of formData.entries()) {
      if (key !== 'gambar') {
        data[key] = value;
      }
    }

    const file = formData.get('gambar') as File | null;
    if (file) {
      const buffer = Buffer.from(await file.arrayBuffer());
      const filename = `${Date.now()}-${file.name.replace(/\s/g, '_')}`;
      const uploadPath = path.join(process.cwd(), 'public/uploads', filename);
      
      await writeFile(uploadPath, buffer);
      data.gambar = filename;
    }

    const validatedData = barangSchema.parse(data);

    const newBarang = await prisma.barang.create({
      data: validatedData,
    });

    return NextResponse.json(newBarang, { status: 201 });
  } catch (error) {
    console.error("Error creating barang:", error);
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: error.issues }, { status: 400 });
    }
    return NextResponse.json(
      { error: "Gagal membuat data barang" },
      { status: 500 }
    );
  }
} 
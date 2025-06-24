import { NextResponse, NextRequest } from "next/server";
import prisma from "@/lib/prisma";
import { writeFile, unlink } from 'fs/promises';
import path from 'path';
import { z } from 'zod';

const barangSchema = z.object({
  sku: z.string(),
  nama: z.string(),
  kategori: z.string(),
  satuan: z.string(),
  jenis: z.string(),
  hargaBeli: z.coerce.number(),
  gambar: z.string().optional(),
});

export async function PUT(request: NextRequest, { params }: { params: { id: string } }) {
  try {
    const formData = await request.formData();
    const data: Record<string, any> = {};
    for (const [key, value] of formData.entries()) {
      if (key !== 'gambar') {
        data[key] = value;
      }
    }

    const existingBarang = await prisma.barang.findUnique({
        where: { id: params.id }
    });

    if (!existingBarang) {
        return NextResponse.json({ error: "Barang tidak ditemukan" }, { status: 404 });
    }

    const file = formData.get('gambar') as File | null;
    if (file) {
      const buffer = Buffer.from(await file.arrayBuffer());
      const filename = `${Date.now()}-${file.name.replace(/\s/g, '_')}`;
      const uploadPath = path.join(process.cwd(), 'public/uploads', filename);
      
      await writeFile(uploadPath, buffer);
      data.gambar = filename;

      if (existingBarang.gambar) {
        const oldPath = path.join(process.cwd(), 'public/uploads', existingBarang.gambar);
        try {
            await unlink(oldPath);
        } catch (err) {
            console.error("Gagal menghapus gambar lama:", err);
        }
      }
    }

    const validatedData = barangSchema.parse(data);

    const updatedBarang = await prisma.barang.update({
      where: { id: params.id },
      data: validatedData,
    });

    return NextResponse.json(updatedBarang);
  } catch (error) {
    console.error("Error updating barang:", error);
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: error.issues }, { status: 400 });
    }
    return NextResponse.json(
      { error: "Gagal memperbarui data barang" },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest, { params }: { params: { id: string } }) {
    try {
        const deletedBarang = await prisma.barang.delete({
            where: { id: params.id }
        });

        if (deletedBarang.gambar) {
            const oldPath = path.join(process.cwd(), 'public/uploads', deletedBarang.gambar);
            try {
                await unlink(oldPath);
            } catch (err) {
                console.error("Gagal menghapus gambar terkait:", err);
            }
        }

        return NextResponse.json({ message: "Barang berhasil dihapus" });
    } catch (error) {
        console.error("Error deleting barang:", error);
        return NextResponse.json(
          { error: "Gagal menghapus data barang" },
          { status: 500 }
        );
    }
} 
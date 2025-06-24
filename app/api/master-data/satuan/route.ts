import { NextResponse, NextRequest } from "next/server";
import prisma from "@/lib/prisma";
import { z } from 'zod';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const satuan = await prisma.satuan.findMany({
      orderBy: {
        nama: "asc",
      },
    });

    return NextResponse.json({
      data: satuan,
    });
  } catch (error) {
    console.error("Error fetching satuan:", error);
    return NextResponse.json(
      { error: "Gagal mengambil data satuan" },
      { status: 500 }
    );
  }
}

const postSchema = z.object({
  nama: z.string().min(1, "Nama satuan tidak boleh kosong"),
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const validatedData = postSchema.parse(body);

    const existing = await prisma.satuan.findFirst({
      where: { nama: { equals: validatedData.nama, mode: 'insensitive' } },
    });

    if (existing) {
      return NextResponse.json(
        { error: `Satuan "${validatedData.nama}" sudah ada.` },
        { status: 409 }
      );
    }

    const newSatuan = await prisma.satuan.create({
      data: {
        nama: validatedData.nama,
      },
    });

    return NextResponse.json(newSatuan, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: error.issues }, { status: 400 });
    }
    console.error("Error creating satuan:", error);
    return NextResponse.json(
      { error: "Gagal membuat data satuan" },
      { status: 500 }
    );
  }
} 
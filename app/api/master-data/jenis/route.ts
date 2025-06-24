import { NextResponse, NextRequest } from "next/server";
import prisma from "@/lib/prisma";
import { z } from 'zod';

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const jenis = await prisma.jenis.findMany({
      orderBy: {
        nama: "asc",
      },
    });

    return NextResponse.json({
      data: jenis,
    });
  } catch (error) {
    console.error("Error fetching jenis:", error);
    return NextResponse.json(
      { error: "Gagal mengambil data jenis" },
      { status: 500 }
    );
  }
}

const postSchema = z.object({
  nama: z.string().min(1, "Nama jenis tidak boleh kosong"),
});

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const validatedData = postSchema.parse(body);

    const existing = await prisma.jenis.findFirst({
        where: { nama: { equals: validatedData.nama, mode: 'insensitive' } },
    });

    if (existing) {
        return NextResponse.json(
            { error: `Jenis "${validatedData.nama}" sudah ada.` },
            { status: 409 }
        );
    }

    const newJenis = await prisma.jenis.create({
      data: {
        nama: validatedData.nama,
      },
    });

    return NextResponse.json(newJenis, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
        return NextResponse.json({ error: error.issues }, { status: 400 });
    }
    console.error("Error creating jenis:", error);
    return NextResponse.json(
      { error: "Gagal membuat data jenis" },
      { status: 500 }
    );
  }
} 
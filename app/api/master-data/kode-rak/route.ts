import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const kodeRak = await prisma.kodeRak.findMany({
      orderBy: {
        nama: "asc",
      },
    });

    return NextResponse.json({
      data: kodeRak,
    });
  } catch (error) {
    console.error("Error fetching kode-rak:", error);
    return NextResponse.json(
      { error: "Gagal mengambil data kode rak" },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { kode, keterangan } = body;

    if (!kode || !keterangan) {
      return NextResponse.json(
        { error: "Kode dan keterangan harus diisi" },
        { status: 400 }
      );
    }

    const newRak = await prisma.kodeRak.create({
      data: {
        kode,
        nama: keterangan,
        kategori: "BAHAN_BAKU", // Default, bisa disesuaikan
      },
    });

    return NextResponse.json(newRak, { status: 201 });
  } catch (error) {
    console.error("Error creating rak:", error);
    return NextResponse.json(
      { error: "Gagal membuat kode rak" },
      { status: 500 }
    );
  }
} 
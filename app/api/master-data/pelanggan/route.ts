import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const pelanggan = await prisma.pelanggan.findMany({
      orderBy: {
        nama: "asc",
      },
    });

    return NextResponse.json({
      data: pelanggan,
    });
  } catch (error) {
    console.error("Error fetching pelanggan:", error);
    return NextResponse.json(
      { error: "Gagal mengambil data pelanggan" },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { nama, alamat, telepon, email } = body;

    if (!nama || !alamat || !telepon) {
      return NextResponse.json({ error: 'Nama, alamat, dan telepon wajib diisi' }, { status: 400 });
    }

    const pelanggan = await prisma.pelanggan.create({
      data: {
        nama,
        alamat,
        telepon,
        email: email || null,
      },
    });

    return NextResponse.json({ data: pelanggan }, { status: 201 });
  } catch (error) {
    console.error('Error menambah pelanggan:', error);
    return NextResponse.json({ error: 'Gagal menambah pelanggan' }, { status: 500 });
  }
} 
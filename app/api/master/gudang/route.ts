import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export const dynamic = 'force-dynamic';

export async function GET() {
  try {
    const gudangList = await prisma.gudang.findMany({
      orderBy: {
        nama: "asc",
      },
    });

    const gudangWithCounts = await Promise.all(
      gudangList.map(async (gudang) => {
        const aggregate = await prisma.stokGudang.aggregate({
          _sum: {
            stok: true,
          },
          _count: {
            barangId: true,
          },
          where: {
            gudangId: gudang.id,
          },
        });

        return {
          ...gudang,
          jumlahBarang: aggregate._count.barangId || 0,
          jumlahStok: aggregate._sum.stok || 0,
        };
      })
    );

    return NextResponse.json({
      data: gudangWithCounts,
    });
  } catch (error) {
    console.error("Error fetching gudang:", error);
    return NextResponse.json(
      { error: "Gagal mengambil data gudang" },
      { status: 500 }
    );
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const { kode, nama, kategori, alamat } = body;
    if (!kode || !nama || !kategori || !alamat) {
      return NextResponse.json({ error: "Data tidak lengkap" }, { status: 400 });
    }
    // Cek kode unik
    const existing = await prisma.gudang.findUnique({ where: { kode } });
    if (existing) {
      return NextResponse.json({ error: "Kode gudang sudah ada" }, { status: 400 });
    }
    const gudang = await prisma.gudang.create({
      data: { kode, nama, kategori, alamat },
    });
    return NextResponse.json({ data: gudang });
  } catch (error) {
    console.error("Error creating gudang:", error);
    return NextResponse.json({ error: "Gagal menambah gudang" }, { status: 500 });
  }
} 
import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import prisma from "@/lib/prisma";

export async function GET() {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const stokMasuk = await prisma.stokMasuk.findMany({
      include: {
        gudang: {
          select: {
            kode: true,
            nama: true,
          },
        },
        barang: {
          select: {
            kode: true,
            nama: true,
            satuan: true,
          },
        },
      },
      orderBy: {
        tanggal: 'desc',
      },
    });

    return NextResponse.json(stokMasuk);
  } catch (error) {
    console.error("Error fetching stok masuk:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const body = await request.json();
    const { tanggal, gudangId, barangId, jumlah, keterangan } = body;

    if (!tanggal || !gudangId || !barangId || !jumlah || !keterangan) {
      return NextResponse.json(
        { error: "Semua field harus diisi" },
        { status: 400 }
      );
    }

    // Update stok barang
    const barang = await prisma.barang.findUnique({
      where: { id: barangId },
      select: { stok: true },
    });

    if (!barang) {
      return NextResponse.json(
        { error: "Barang tidak ditemukan" },
        { status: 404 }
      );
    }

    const stokMasuk = await prisma.$transaction(async (tx) => {
      // Create stok masuk record
      const stokMasuk = await tx.stokMasuk.create({
        data: {
          tanggal: new Date(tanggal),
          gudangId,
          barangId,
          jumlah: parseInt(jumlah),
          keterangan,
        },
        include: {
          gudang: {
            select: {
              kode: true,
              nama: true,
            },
          },
          barang: {
            select: {
              kode: true,
              nama: true,
              satuan: true,
            },
          },
        },
      });

      // Update barang stok
      await tx.barang.update({
        where: { id: barangId },
        data: {
          stok: barang.stok + parseInt(jumlah),
        },
      });

      return stokMasuk;
    });

    return NextResponse.json(stokMasuk);
  } catch (error) {
    console.error("Error creating stok masuk:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
} 
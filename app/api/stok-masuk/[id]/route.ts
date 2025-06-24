import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import prisma from "@/lib/prisma";

export async function DELETE(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { id } = params;

    const result = await prisma.$transaction(async (tx) => {
      // 1. Ambil data transaksi stok masuk yang akan dihapus
      const stokMasuk = await tx.stokMasuk.findUnique({
        where: { id },
        include: {
          items: true,
        },
      });

      if (!stokMasuk) {
        throw new Error("Transaksi stok masuk tidak ditemukan");
      }

      // 2. Kurangi stok di gudang untuk setiap item
      for (const item of stokMasuk.items) {
        const barang = await tx.barang.findUnique({ where: { sku: item.sku } });
        if (!barang) continue;

        const stokGudang = await tx.stokGudang.findFirst({
          where: {
            barangId: barang.id,
            gudangId: stokMasuk.gudang,
            kodeRakId: item.kodeRakId,
          },
        });

        if (stokGudang) {
          await tx.stokGudang.update({
            where: { id: stokGudang.id },
            data: {
              stok: {
                decrement: item.qty,
              },
            },
          });
        }
      }

      // 3. Hapus transaksi stok masuk (items akan terhapus otomatis karena onDelete: Cascade)
      await tx.stokMasuk.delete({
        where: { id },
      });

      return { message: "Transaksi berhasil dihapus" };
    });

    return NextResponse.json(result);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Internal server error";
    console.error("Error deleting stok masuk:", error);
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
}

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { id } = params;
    const stokMasuk = await prisma.stokMasuk.findUnique({
      where: { id },
      include: {
        items: {
          include: {
            kodeRak: true,
          },
        },
      },
    });

    if (!stokMasuk) {
      return NextResponse.json({ error: "Transaksi stok masuk tidak ditemukan" }, { status: 404 });
    }

    return NextResponse.json(stokMasuk);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : "Internal server error";
    console.error("Error fetching detail stok masuk:", error);
    return NextResponse.json(
      { error: errorMessage },
      { status: 500 }
    );
  }
} 
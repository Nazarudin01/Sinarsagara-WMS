import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export async function DELETE(
  request: Request,
  { params }: { params: { id: string } }
) {
  const id = params.id;

  try {
    // Gunakan transaksi untuk memastikan kedua operasi berhasil atau tidak sama sekali
    const result = await prisma.$transaction(async (tx) => {
      // 1. Hapus semua entri StokGudang yang terkait dengan gudang ini
      await tx.stokGudang.deleteMany({
        where: {
          gudangId: id,
        },
      });

      // 2. Hapus gudang itu sendiri
      const deletedGudang = await tx.gudang.delete({
        where: {
          id: id,
        },
      });

      return deletedGudang;
    });

    return NextResponse.json(result, { status: 200 });
  } catch (error) {
    console.error("Error deleting gudang:", error);
    // Cek jika gudang tidak ditemukan
    if (error instanceof prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2025') {
        return NextResponse.json(
          { error: "Gudang tidak ditemukan." },
          { status: 404 }
        );
      }
    }
    // Error umum lainnya
    return NextResponse.json(
      { error: "Gagal menghapus gudang beserta data terkait." },
      { status: 500 }
    );
  }
} 
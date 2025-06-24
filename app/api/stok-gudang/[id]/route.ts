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

    if (!id) {
      return NextResponse.json({ error: "ID stok gudang diperlukan" }, { status: 400 });
    }

    // Lakukan penghapusan
    await prisma.stokGudang.delete({
      where: { id },
    });

    return NextResponse.json({ message: "Stok barang di gudang berhasil dihapus" });
    
  } catch (error) {
    console.error("[STOK_GUDANG_DELETE]", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

export async function PUT(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { id } = params;
    const body = await request.json();
    const { kodeRakId } = body;

    if (!id || !kodeRakId) {
      return NextResponse.json({ error: "ID stok gudang dan ID rak baru diperlukan" }, { status: 400 });
    }

    const updatedStokGudang = await prisma.stokGudang.update({
      where: { id },
      data: { kodeRakId },
    });

    return NextResponse.json(updatedStokGudang);
    
  } catch (error) {
    console.error("[STOK_GUDANG_UPDATE]", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const { id: gudangId } = params;
    if (!gudangId) {
      return NextResponse.json({ error: "ID gudang diperlukan" }, { status: 400 });
    }

    const stokGudang = await prisma.stokGudang.findMany({
      where: { gudangId },
      include: {
        barang: true,
        kodeRak: true,
      },
      orderBy: {
        nama: "asc",
      },
    });

    const result = stokGudang.map((item) => ({
      id: item.id,
      barangId: item.barangId,
      gambar: item.barang.gambar,
      kodeRak: item.kodeRak?.kode || "-",
      sku: item.barang.sku,
      nama: item.barang.nama,
      stok: item.stok,
      satuan: item.barang.satuan,
    }));

    return NextResponse.json({ data: result });
  } catch (error) {
    console.error("[STOK_GUDANG_GET]", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
} 
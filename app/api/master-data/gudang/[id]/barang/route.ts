import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import prisma from "@/lib/prisma";

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { searchParams } = new URL(request.url);
    const searchQuery = searchParams.get("q");

    // Ambil stokGudang berdasarkan gudangId
    const stokGudang = await prisma.stokGudang.findMany({
      where: {
        gudangId: params.id,
        stok: { gt: 0 },
        ...(searchQuery && {
          OR: [
            { barang: { nama: { contains: searchQuery, mode: "insensitive" } } },
            { barang: { sku: { contains: searchQuery, mode: "insensitive" } } },
            { kodeRak: { kode: { contains: searchQuery, mode: "insensitive" } } },
          ],
        }),
      },
      include: {
        barang: true,
        kodeRak: true, // Memastikan data rak di-include
      },
      orderBy: {
        barang: {
          nama: "asc",
        },
      },
    });

    // Map setiap entri stokGudang ke format respons yang benar
    const barangsData = stokGudang
      .map((sg) => {
        if (!sg.barang) return null;
        return {
          ...sg.barang,
          stokGudangId: sg.id,
          harga: sg.barang.hargaBeli,
          kodeRak: sg.kodeRak?.kode || "", // Menggunakan kode dari relasi
          stok: sg.stok,
        };
      })
      .filter(Boolean);

    return NextResponse.json(barangsData);
  } catch (error) {
    console.error("Error fetching barang:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
} 
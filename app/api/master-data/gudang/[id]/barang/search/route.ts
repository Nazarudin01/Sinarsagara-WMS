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
    const query = searchParams.get("q");

    if (!query) {
      return NextResponse.json({ error: "Query parameter is required" }, { status: 400 });
    }

    const barang = await prisma.barang.findMany({
      where: {
        gudangId: params.id,
        OR: [
          { kode: { contains: query, mode: 'insensitive' } },
          { nama: { contains: query, mode: 'insensitive' } },
          { kategori: { contains: query, mode: 'insensitive' } },
        ],
      },
      select: {
        id: true,
        kode: true,
        nama: true,
        kategori: true,
        satuan: true,
        harga: true,
        stok: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: {
        nama: 'asc',
      },
    });

    return NextResponse.json(barang);
  } catch (error) {
    console.error("Error searching barang:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
} 
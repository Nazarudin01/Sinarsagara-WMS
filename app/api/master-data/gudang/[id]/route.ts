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

    const gudang = await prisma.gudang.findUnique({
      where: {
        id: params.id,
      },
      select: {
        id: true,
        kode: true,
        nama: true,
        kategori: true,
        alamat: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!gudang) {
      return NextResponse.json({ error: "Gudang tidak ditemukan" }, { status: 404 });
    }

    return NextResponse.json(gudang);
  } catch (error) {
    console.error("Error fetching gudang:", error);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
} 
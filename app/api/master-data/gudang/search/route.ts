import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import prisma from "@/lib/prisma";

export async function GET(req: Request) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return new NextResponse("Unauthorized", { status: 401 });
    }

    const { searchParams } = new URL(req.url);
    const query = searchParams.get("q");

    if (!query) {
      return new NextResponse("Missing search query", { status: 400 });
    }

    const gudangs = await prisma.gudang.findMany({
      where: {
        OR: [
          { kode: { contains: query, mode: "insensitive" } },
          { nama: { contains: query, mode: "insensitive" } },
          { kategori: { contains: query, mode: "insensitive" } },
          { alamat: { contains: query, mode: "insensitive" } },
        ],
      },
      orderBy: {
        nama: "asc",
      },
    });

    return NextResponse.json(gudangs);
  } catch (error) {
    console.error("[GUDANG_SEARCH]", error);
    return new NextResponse("Internal error", { status: 500 });
  }
} 
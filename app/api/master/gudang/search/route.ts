import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const query = searchParams.get("q");

  if (!query) {
    return NextResponse.json({ error: "Query is required" }, { status: 400 });
  }

  try {
    const gudangs = await prisma.gudang.findMany({
      where: {
        OR: [
          { kode: { contains: query, mode: "insensitive" } },
          { nama: { contains: query, mode: "insensitive" } },
        ],
      },
    });
    return NextResponse.json({ data: gudangs });
  } catch (error) {
    console.error("Error searching gudang:", error);
    return NextResponse.json(
      { error: "Gagal mencari data gudang" },
      { status: 500 }
    );
  }
} 
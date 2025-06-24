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

    const pelanggans = await prisma.pelanggan.findMany({
      where: {
        OR: [
          { nama: { contains: query, mode: "insensitive" } },
          { alamat: { contains: query, mode: "insensitive" } },
          { telepon: { contains: query, mode: "insensitive" } },
          { email: { contains: query, mode: "insensitive" } },
        ],
      },
      orderBy: {
        nama: "asc",
      },
      select: {
        id: true,
        nama: true,
        alamat: true,
        telepon: true,
        email: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return NextResponse.json({ data: pelanggans });
  } catch (error) {
    console.error("[PELANGGAN_SEARCH]", error);
    return new NextResponse("Internal error", { status: 500 });
  }
} 
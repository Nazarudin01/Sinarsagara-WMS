import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";

// GET /api/jenis
export async function GET() {
  try {
    console.log("Fetching jenis data...");
    const jenis = await prisma.jenis.findMany({
      orderBy: {
        nama: 'asc'
      }
    });
    console.log("Jenis data fetched successfully:", jenis);
    return NextResponse.json(jenis);
  } catch (error) {
    console.error("Error in GET /api/jenis:", error);
    return NextResponse.json(
      { error: "Gagal mengambil data jenis" },
      { status: 500 }
    );
  }
}

// POST /api/jenis
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { nama } = body;

    if (!nama) {
      return NextResponse.json(
        { error: "Nama jenis harus diisi" },
        { status: 400 }
      );
    }

    const jenis = await prisma.jenis.create({
      data: {
        nama: nama
      }
    });

    return NextResponse.json(jenis);
  } catch (error: any) {
    console.error("Error in POST /api/jenis:", error);
    
    if (error.code === 'P2002') {
      return NextResponse.json(
        { error: "Jenis dengan nama tersebut sudah ada" },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { error: "Gagal menambah jenis" },
      { status: 500 }
    );
  }
} 
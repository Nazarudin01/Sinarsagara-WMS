import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";

// GET /api/satuan
export async function GET() {
  try {
    console.log("Fetching satuan data...");
    const satuan = await prisma.satuan.findMany({
      orderBy: {
        nama: 'asc'
      }
    });
    console.log("Satuan data fetched successfully:", satuan);
    return NextResponse.json(satuan);
  } catch (error) {
    console.error("Error in GET /api/satuan:", error);
    return NextResponse.json(
      { error: "Gagal mengambil data satuan" },
      { status: 500 }
    );
  }
}

// POST /api/satuan
export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { nama } = body;

    if (!nama) {
      return NextResponse.json(
        { error: "Nama satuan harus diisi" },
        { status: 400 }
      );
    }

    const satuan = await prisma.satuan.create({
      data: {
        nama: nama
      }
    });

    return NextResponse.json(satuan);
  } catch (error: any) {
    console.error("Error in POST /api/satuan:", error);
    
    if (error.code === 'P2002') {
      return NextResponse.json(
        { error: "Satuan dengan nama tersebut sudah ada" },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { error: "Gagal menambah satuan" },
      { status: 500 }
    );
  }
} 
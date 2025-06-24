import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export async function GET() {
  try {
    const lastGudang = await prisma.gudang.findFirst({
      orderBy: {
        kode: 'desc'
      }
    });

    let newKode = "G001";
    if (lastGudang && lastGudang.kode) {
      // Ambil angka setelah huruf G (atau prefix lain)
      const match = lastGudang.kode.match(/G(\d+)/);
      const lastNumber = match ? parseInt(match[1]) : 0;
      if (lastNumber > 0) {
        newKode = "G" + String(lastNumber + 1).padStart(3, '0');
      } else {
        newKode = "G001";
      }
    }

    return NextResponse.json({ kode: newKode });
  } catch (error) {
    console.error("Error generating kode gudang:", error);
    return NextResponse.json(
      { error: "Gagal generate kode gudang" },
      { status: 500 }
    );
  }
} 
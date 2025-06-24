import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import prisma from "@/lib/prisma";

export async function GET() {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return new NextResponse("Unauthorized", { status: 401 });
    }

    // Get the last gudang to determine the next number
    const lastGudang = await prisma.gudang.findFirst({
      orderBy: {
        kode: 'desc'
      }
    });

    let nextNumber = 1;
    if (lastGudang) {
      const lastNumber = parseInt(lastGudang.kode.split('-')[1]);
      if (!isNaN(lastNumber)) {
        nextNumber = lastNumber + 1;
      }
    }

    // Format the code as G-XXX
    const kode = `G-${nextNumber.toString().padStart(3, '0')}`;

    return NextResponse.json({ kode });
  } catch (error) {
    console.error("[GENERATE_KODE]", error);
    return new NextResponse("Internal error", { status: 500 });
  }
} 
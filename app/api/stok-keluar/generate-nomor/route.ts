import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { format } from "date-fns";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const now = new Date();
    const month = format(now, "MM");
    const year = format(now, "yy");

    const prefix = `SK-${month}${year}-`;

    const lastTransaction = await prisma.transaksiKeluar.findFirst({
      where: {
        nomor: {
          startsWith: prefix,
        },
      },
      orderBy: {
        nomor: "desc",
      },
      select: {
        nomor: true,
      },
    });

    let newSequence = 1;
    if (lastTransaction) {
      const lastSequence = parseInt(lastTransaction.nomor.split("-")[2], 10);
      newSequence = lastSequence + 1;
    }

    const newNomor = `${prefix}${newSequence.toString().padStart(3, "0")}`;

    return NextResponse.json({ nomor: newNomor });
  } catch (error) {
    console.error("Error generating transaction number:", error);
    return NextResponse.json(
      { error: "Gagal membuat nomor transaksi" },
      { status: 500 }
    );
  }
} 
import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { format } from "date-fns";

export async function GET() {
  try {
    const today = new Date();
    const month = format(today, "MM");
    const year = format(today, "yy");

    // Get the last nomor for this month
    const lastStokMasuk = await prisma.stokMasuk.findFirst({
      where: {
        nomor: {
          startsWith: `SM-${month}${year}-`,
        },
      },
      orderBy: {
        nomor: "desc",
      },
    });

    let sequence = 1;
    if (lastStokMasuk) {
      const lastSequence = parseInt(lastStokMasuk.nomor.split("-")[2]);
      sequence = lastSequence + 1;
    }

    const nomor = `SM-${month}${year}-${sequence.toString().padStart(3, "0")}`;
    return NextResponse.json({ nomor });
  } catch (error) {
    console.error("Error generating nomor:", error);
    return NextResponse.json(
      { error: "Failed to generate nomor" },
      { status: 500 }
    );
  }
} 
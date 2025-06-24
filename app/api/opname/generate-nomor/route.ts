import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { format } from "date-fns";

export async function GET() {
  try {
    const now = new Date();
    const month = format(now, "MM");
    const year = format(now, "yy");
    const prefix = `OPN-${month}${year}-`;

    const lastOpname = await prisma.stokOpname.findFirst({
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
    if (lastOpname) {
      const lastSequence = parseInt(lastOpname.nomor.split("-")[2], 10);
      newSequence = lastSequence + 1;
    }

    const newNomor = `${prefix}${newSequence.toString().padStart(3, "0")}`;
    return NextResponse.json({ nomor: newNomor });
  } catch (error) {
    console.error("[OPNAME_GENERATE_NOMOR]", error);
    return NextResponse.json({ error: "Gagal generate nomor opname" }, { status: 500 });
  }
} 
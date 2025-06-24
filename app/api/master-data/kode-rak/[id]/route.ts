import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export async function DELETE(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const { id } = params;
    await prisma.kodeRak.delete({
      where: { id },
    });
    return NextResponse.json({ message: "Rak berhasil dihapus" });
  } catch (error) {
    console.error("Error deleting rak:", error);
    return NextResponse.json(
      { error: "Gagal menghapus rak" },
      { status: 500 }
    );
  }
} 
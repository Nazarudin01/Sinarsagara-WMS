import { NextRequest, NextResponse } from "next/server"
import prisma from "@/lib/prisma"
import { getServerSession } from "next-auth"
import { authOptions } from "@/lib/auth"

export async function GET(req: NextRequest) {
  try {
    const session = await getServerSession(authOptions)

    if (!session) {
      return new NextResponse("Unauthorized", { status: 401 })
    }

    const totalProducts = await prisma.barang.count()
    const totalSuppliers = await prisma.pemasok.count()
    const totalWarehouses = await prisma.gudang.count()
    // Total stok keseluruhan dari StokGudang
    const stokSum = await prisma.stokGudang.aggregate({ _sum: { stok: true } })
    const totalStock = stokSum._sum.stok || 0

    return NextResponse.json({
      totalProducts,
      totalSuppliers,
      totalWarehouses,
      totalStock,
    })
  } catch (error) {
    console.error("[DASHBOARD_STATS]", error)
    return new NextResponse("Internal Error", { status: 500 })
  }
} 
import { NextResponse } from "next/server"
import { getServerSession } from "next-auth"
import { authOptions } from "@/lib/auth"
import prisma from "@/lib/prisma"

export async function GET() {
  try {
    const pemasok = await prisma.pemasok.findMany({
      orderBy: {
        nama: "asc",
      },
    })
    return NextResponse.json({
      data: pemasok,
    })
  } catch (error) {
    return NextResponse.json(
      { error: "Gagal mengambil data pemasok" },
      { status: 500 }
    )
  }
}

export async function POST(req: Request) {
  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      return new NextResponse("Unauthorized", { status: 401 })
    }

    const body = await req.json()
    console.log("[PEMASOK_POST] Request body:", body)
    const { nama, alamat, telepon, email } = body

    if (!nama || !alamat || !telepon || !email) {
      console.log("[PEMASOK_POST] Missing fields:", { nama, alamat, telepon, email })
      return new NextResponse("Missing required fields", { status: 400 })
    }

    try {
      const pemasok = await prisma.pemasok.create({
        data: {
          nama,
          alamat,
          telepon,
          email,
        },
      })
      console.log("[PEMASOK_POST] Created pemasok:", pemasok)
      return NextResponse.json(pemasok)
    } catch (dbError) {
      console.error("[PEMASOK_POST] Database error:", dbError)
      return new NextResponse("Database error", { status: 500 })
    }
  } catch (error) {
    console.error("[PEMASOK_POST] Error:", error)
    return new NextResponse("Internal error", { status: 500 })
  }
}

export async function DELETE(req: Request) {
  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      return new NextResponse("Unauthorized", { status: 401 })
    }

    const { searchParams } = new URL(req.url)
    const id = searchParams.get("id")

    if (!id) {
      return new NextResponse("Missing pemasok ID", { status: 400 })
    }

    await prisma.pemasok.delete({
      where: { id },
    })

    return new NextResponse(null, { status: 204 })
  } catch (error) {
    console.error("[PEMASOK_DELETE]", error)
    return new NextResponse("Internal error", { status: 500 })
  }
} 
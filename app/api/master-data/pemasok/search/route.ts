import { NextResponse } from "next/server"
import { getServerSession } from "next-auth"
import { authOptions } from "@/lib/auth"
import prisma from "@/lib/prisma"

export async function GET(request: Request) {
  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      return new NextResponse("Unauthorized", { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const search = searchParams.get("q") || ""

    const pemasoks = await prisma.pemasok.findMany({
      where: {
        OR: [
          {
            nama: {
              contains: search,
              mode: 'insensitive'
            }
          },
          {
            alamat: {
              contains: search,
              mode: 'insensitive'
            }
          },
          {
            telepon: {
              contains: search,
              mode: 'insensitive'
            }
          },
          {
            email: {
              contains: search,
              mode: 'insensitive'
            }
          }
        ]
      },
      orderBy: {
        nama: "asc",
      },
    })

    return NextResponse.json({ data: pemasoks })
  } catch (error) {
    console.error("[PEMASOK_SEARCH]", error)
    return new NextResponse("Internal error", { status: 500 })
  }
} 
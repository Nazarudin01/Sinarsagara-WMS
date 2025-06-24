import prisma from "@/lib/prisma"
import { NextResponse } from "next/server"
import { getServerSession } from "next-auth"
import { authOptions } from "@/lib/auth"
import { writeFile } from "fs/promises"
import path from "path"

export async function PATCH(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const formData = await request.formData()
    const kategori = formData.get('kategori') as string
    const satuan = formData.get('satuan') as string
    const jenis = formData.get('jenis') as string
    const hargaBeli = formData.get('hargaBeli') ? parseFloat(formData.get('hargaBeli') as string) : 0
    const gambar = formData.get('gambar') as File | null

    // Handle file upload
    let gambarUrl = null
    if (gambar) {
      const bytes = await gambar.arrayBuffer()
      const buffer = Buffer.from(bytes)

      // Generate unique filename
      const timestamp = Date.now()
      const originalName = gambar.name
      const extension = path.extname(originalName)
      const filename = `${timestamp}${extension}`
      
      // Save file to public/uploads
      const uploadDir = path.join(process.cwd(), 'public', 'uploads')
      const filepath = path.join(uploadDir, filename)
      
      await writeFile(filepath, buffer)
      gambarUrl = filename
    }

    // Update barang
    const barang = await prisma.barang.update({
      where: {
        id: params.id
      },
      data: {
        kategori,
        satuan,
        jenis,
        hargaBeli,
        ...(gambarUrl && { gambar: gambarUrl })
      }
    })

    return NextResponse.json(barang)
  } catch (error: any) {
    console.error("Error in PATCH /api/barang/[id]:", error)
    return NextResponse.json(
      { error: "Gagal mengupdate barang: " + error.message },
      { status: 500 }
    )
  }
}

export async function DELETE(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    await prisma.barang.delete({
      where: {
        id: params.id
      }
    })

    return NextResponse.json({ message: "Barang berhasil dihapus" })
  } catch (error: any) {
    console.error("Error in DELETE /api/barang/[id]:", error)
    return NextResponse.json(
      { error: "Gagal menghapus barang: " + error.message },
      { status: 500 }
    )
  }
} 
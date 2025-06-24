import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { writeFile } from "fs/promises";
import path from "path";

export async function GET() {
  try {
    console.log("Fetching barang data...");
    const barang = await prisma.barang.findMany({
      orderBy: {
        nama: 'asc'
      },
      include: {
        stok: true,
      },
    });
    console.log("Barang data fetched successfully:", barang);
    return NextResponse.json(barang);
  } catch (error) {
    console.error("Error in GET /api/barang:", error);
    return NextResponse.json(
      { error: "Gagal mengambil data barang" },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    console.log("Received POST request to /api/barang");
    const formData = await request.formData();
    
    // Log semua data yang diterima
    console.log("Form data received:", {
      sku: formData.get('sku'),
      nama: formData.get('nama'),
      kategori: formData.get('kategori'),
      satuan: formData.get('satuan'),
      jenis: formData.get('jenis'),
      hargaBeli: formData.get('hargaBeli'),
      gambar: formData.get('gambar')
    });

    const sku = formData.get('sku') as string;
    const nama = formData.get('nama') as string;
    const kategori = formData.get('kategori') as string;
    const satuan = formData.get('satuan') as string;
    const jenis = formData.get('jenis') as string;
    const hargaBeli = formData.get('hargaBeli') ? parseFloat(formData.get('hargaBeli') as string) : 0;
    const gambar = formData.get('gambar') as File | null;

    // Validasi input
    if (!sku) {
      return NextResponse.json(
        { error: "SKU harus diisi" },
        { status: 400 }
      );
    }
    if (!nama) {
      return NextResponse.json(
        { error: "Nama barang harus diisi" },
        { status: 400 }
      );
    }
    if (!kategori) {
      return NextResponse.json(
        { error: "Kategori harus diisi" },
        { status: 400 }
      );
    }
    if (!satuan) {
      return NextResponse.json(
        { error: "Satuan harus diisi" },
        { status: 400 }
      );
    }
    if (!jenis) {
      return NextResponse.json(
        { error: "Jenis harus diisi" },
        { status: 400 }
      );
    }

    // Handle file upload
    let gambarUrl = null;
    if (gambar) {
      const bytes = await gambar.arrayBuffer();
      const buffer = Buffer.from(bytes);

      // Generate unique filename
      const timestamp = Date.now();
      const originalName = gambar.name;
      const extension = path.extname(originalName);
      const filename = `${timestamp}${extension}`;
      
      // Save file to public/uploads
      const uploadDir = path.join(process.cwd(), 'public', 'uploads');
      const filepath = path.join(uploadDir, filename);
      
      await writeFile(filepath, buffer);
      gambarUrl = filename;
      
      console.log("File saved:", filepath);
    }

    console.log("Creating new barang with data:", {
      sku,
      nama,
      kategori,
      satuan,
      jenis,
      hargaBeli,
      gambar: gambarUrl
    });

    const barang = await prisma.barang.create({
      data: {
        sku,
        nama,
        kategori,
        satuan,
        jenis,
        hargaBeli,
        gambar: gambarUrl,
      }
    });

    console.log("Barang created successfully:", barang);
    return NextResponse.json(barang);
  } catch (error: any) {
    console.error("Error in POST /api/barang:", error);
    
    if (error.code === 'P2002') {
      return NextResponse.json(
        { error: "Barang dengan SKU tersebut sudah ada" },
        { status: 400 }
      );
    }

    return NextResponse.json(
      { error: "Gagal menambah barang: " + error.message },
      { status: 500 }
    );
  }
} 
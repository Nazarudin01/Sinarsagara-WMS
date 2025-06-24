import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import prisma from '@/lib/prisma';
import { authOptions } from '@/lib/auth';

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    const gudangId = params.id;

    // Verify gudang exists
    const gudang = await prisma.gudang.findUnique({
      where: { id: gudangId },
    });

    if (!gudang) {
      return new NextResponse('Gudang tidak ditemukan', { status: 404 });
    }

    // Get all stocks for this gudang with barang details
    const stocks = await prisma.stokGudang.findMany({
      where: {
        gudangId: gudangId,
      },
      include: {
        barang: {
          select: {
            id: true,
            nama: true,
            sku: true,
            jenis: true,
          },
        },
      },
      orderBy: {
        barang: {
          nama: 'asc',
        },
      },
    });

    return NextResponse.json(stocks);
  } catch (error) {
    console.error('Error fetching gudang stocks:', error);
    return new NextResponse('Internal Server Error', { status: 500 });
  }
}

export async function POST(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    const gudangId = params.id;
    const body = await request.json();
    const { nama, sku, jenis, kategori, satuan, jumlah } = body;

    if (!nama || !sku || !jenis || !kategori || !satuan || typeof jumlah !== 'number') {
      return new NextResponse('Data barang tidak lengkap', { status: 400 });
    }

    // Cek gudang
    const gudang = await prisma.gudang.findUnique({
      where: { id: gudangId },
    });
    if (!gudang) {
      return new NextResponse('Gudang tidak ditemukan', { status: 404 });
    }

    // Cek SKU unik
    const existingBarang = await prisma.barang.findUnique({
      where: { sku },
    });
    if (existingBarang) {
      return new NextResponse('SKU sudah terdaftar', { status: 400 });
    }

    // Buat barang baru
    const barang = await prisma.barang.create({
      data: { nama, sku, jenis, kategori, satuan },
    });

    // Tambah stok di gudang
    const stok = await prisma.stokGudang.create({
      data: {
        barangId: barang.id,
        gudangId,
        stok: jumlah,
        nama: nama,
        sku: sku,
      },
    });

    return NextResponse.json({ barang, stok });
  } catch (error) {
    console.error('Error creating barang/stok:', error);
    return new NextResponse('Gagal membuat barang baru', { status: 500 });
  }
} 
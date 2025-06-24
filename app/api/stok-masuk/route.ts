import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";
import { authOptions } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { format } from "date-fns";

export async function GET() {
  try {
    const session = await getServerSession(authOptions);

    if (!session) {
      return NextResponse.json(
        { error: "Unauthorized" },
        { status: 401 }
      );
    }

    const data = await prisma.stokMasuk.findMany({
      select: {
        id: true,
        nomor: true,
        tanggal: true,
        pemasok: true,
        gudang: true,
        status: true,
        total: true,
        items: true,
        created_at: true,
        updated_at: true,
      },
      orderBy: {
        tanggal: "desc"
      }
    });

    return NextResponse.json(data);
  } catch (error) {
    console.error("Error fetching stok masuk:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
}

export async function POST(request: Request) {
  try {
    const session = await getServerSession(authOptions);

    if (!session) {
      return NextResponse.json(
        { error: "Unauthorized" },
        { status: 401 }
      );
    }

    const body = await request.json();
    const {
      tanggal,
      pemasok,
      gudang,
      status,
      total,
      items,
      nomor
    } = body;

    if (!tanggal || !pemasok || !gudang || !items || !Array.isArray(items) || items.length === 0) {
      console.error("Payload error: field utama tidak lengkap", { tanggal, pemasok, gudang, items });
      return NextResponse.json(
        { error: "Data tidak lengkap" },
        { status: 400 }
      );
    }

    // Validasi items
    for (const [i, item] of items.entries()) {
      if (
        !item.sku ||
        !item.nama_barang ||
        item.qty === undefined || isNaN(Number(item.qty)) ||
        item.harga === undefined || isNaN(Number(item.harga))
      ) {
        console.error(`Payload error: item ke-${i + 1} tidak valid`, item);
        return NextResponse.json(
          { error: `Data item ke-${i + 1} tidak lengkap atau tidak valid` },
          { status: 400 }
        );
      }
    }

    // Hitung total jika tidak dikirim
    const calculatedTotal = total ?? items.reduce((sum: number, item: any) => sum + (Number(item.qty) * Number(item.harga)), 0);

    // Transaksi: create stokMasuk, items, dan update stok gudang
    const result = await prisma.$transaction(async (tx) => {
      // 1. Create stokMasuk dan items
      const stokMasuk = await tx.stokMasuk.create({
        data: {
          nomor,
          tanggal: new Date(tanggal),
          pemasok,
          gudang,
          status: "COMPLETED",
          total: calculatedTotal,
          items: {
            create: items.map((item: any) => ({
              sku: item.sku,
              nama_barang: item.nama_barang,
              qty: Number(item.qty),
              harga: Number(item.harga),
              kodeRak: item.kodeRakId
                ? {
                    connect: {
                      id: item.kodeRakId,
                    },
                  }
                : undefined,
            })),
          }
        },
        select: {
          id: true,
          nomor: true,
          tanggal: true,
          pemasok: true,
          gudang: true,
          status: true,
          total: true,
          items: true,
          created_at: true,
          updated_at: true,
        }
      });

      // 2. Update/insert stok gudang untuk setiap item
      for (const item of items) {
        // Cari barang dan gudang ID berdasarkan SKU dan ID gudang
        const barang = await tx.barang.findUnique({ where: { sku: item.sku } });
        const gudangData = await tx.gudang.findUnique({ where: { id: gudang } });
        const kodeRak = item.kodeRakId ? await tx.kodeRak.findUnique({ where: { id: item.kodeRakId } }) : null;
        
        if (!barang || !gudangData) {
          throw new Error(`Barang dengan SKU ${item.sku} atau gudang dengan ID ${gudang} tidak ditemukan`);
        }

        const existingStok = await tx.stokGudang.findFirst({
          where: {
            barangId: barang.id,
            gudangId: gudangData.id,
            kodeRakId: item.kodeRakId,
          },
        });

        if (existingStok) {
          await tx.stokGudang.update({
            where: { id: existingStok.id },
            data: { 
              stok: existingStok.stok + Number(item.qty)
            },
          });
        } else {
          await tx.stokGudang.create({
            data: {
              barangId: barang.id,
              gudangId: gudangData.id,
              kodeRakId: item.kodeRakId,
              sku: item.sku,
              nama: item.nama_barang,
              stok: Number(item.qty)
            },
          });
        }

        // Update only updatedAt on Barang (optional)
        await tx.barang.update({
          where: { id: barang.id },
          data: {
            updatedAt: new Date()
          },
        });
      }

      return stokMasuk;
    });

    return NextResponse.json(result);
  } catch (error) {
    console.error("Error creating stok masuk:", error);
    return NextResponse.json(
      { error: "Internal Server Error" },
      { status: 500 }
    );
  }
} 
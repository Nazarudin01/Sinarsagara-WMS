import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { z } from "zod";
import { format } from "date-fns";

// Zod schema for validation, mirroring the frontend
const formSchema = z.object({
  nomor: z.string(),
  tanggal: z.date(),
  pelangganId: z.string().min(1, "Pelanggan harus dipilih"),
  gudangId: z.string().min(1, "Gudang harus dipilih"),
  items: z.array(z.object({
    barangId: z.string().min(1, "Barang harus dipilih"),
    jumlah: z.number().min(1, "Jumlah minimal 1"),
  })).min(1, "Minimal harus ada satu item barang"),
});


export async function POST(request: Request) {
  try {
    const body = await request.json();
    
    // Convert date string back to Date object for validation
    const parsedBody = {
      ...body,
      tanggal: new Date(body.tanggal),
    };

    const validation = formSchema.safeParse(parsedBody);

    if (!validation.success) {
      return new NextResponse(JSON.stringify(validation.error.format()), { status: 400 });
    }

    const { nomor, tanggal, pelangganId, gudangId, items } = validation.data;
    
    // Prisma Transaction
    const result = await prisma.$transaction(async (tx) => {
      // 1. Check for sufficient stock for all items
      for (const item of items) {
        // Use findFirst because the unique constraint involves kodeRakId as well
        const stokGudang = await tx.stokGudang.findFirst({
          where: {
            gudangId: gudangId,
            barangId: item.barangId,
          },
        });

        if (!stokGudang || stokGudang.stok < item.jumlah) {
          // Fetch barang name for a more user-friendly error message
          const barang = await tx.barang.findUnique({ where: { id: item.barangId }});
          throw new Error(`Stok untuk ${barang?.nama || 'barang yang dipilih'} tidak mencukupi di gudang.`);
        }
      }

      // 2. Create TransaksiKeluar record
      const transaksiKeluar = await tx.transaksiKeluar.create({
        data: {
          nomor,
          tanggal,
          pelangganId,
          gudangId,
          total: 0, // Placeholder for total, you can calculate this if needed
        },
      });

      // 3. Create TransaksiKeluarDetail records and update StokGudang
      for (const item of items) {
        // Create item detail
        await tx.transaksiKeluarDetail.create({
          data: {
            transaksiKeluarId: transaksiKeluar.id,
            barangId: item.barangId,
            qty: item.jumlah,
            harga: 0, // Placeholder for harga
          },
        });

        // Update (decrement) stock in StokGudang
        await tx.stokGudang.updateMany({
          where: {
            gudangId: gudangId,
            barangId: item.barangId,
          },
          data: {
            stok: {
              decrement: item.jumlah,
            },
          },
        });
      }

      return transaksiKeluar;
    });

    return NextResponse.json(result, { status: 201 });

  } catch (error) {
    console.error("[STOK_KELUAR_POST]", error);
    if (error instanceof Error && error.message.includes("Stok tidak mencukupi")) {
       return new NextResponse(error.message, { status: 400 });
    }
    return new NextResponse("Internal Server Error", { status: 500 });
  }
}

export async function GET() {
  try {
    const transaksiKeluar = await prisma.transaksiKeluar.findMany({
      include: {
        pelanggan: true,
        details: true,
      },
      orderBy: {
        tanggal: 'desc',
      },
    });

    // Ambil semua gudang sekaligus untuk mapping nama
    const gudangList = await prisma.gudang.findMany({ select: { id: true, nama: true } });
    const gudangMap = Object.fromEntries(gudangList.map(g => [g.id, g.nama]));

    const formattedData = transaksiKeluar.map(item => ({
      id: item.id,
      tanggal: format(item.tanggal, "yyyy-MM-dd"),
      nomor: item.nomor,
      pelanggan: item.pelanggan?.nama || 'Tidak Diketahui',
      gudang: gudangMap[item.gudangId] || 'Tidak Diketahui',
      jumlahBarang: item.details.reduce((sum, detail) => sum + detail.qty, 0),
      status: 'Selesai', // Assuming a status
    }));

    return NextResponse.json({ data: formattedData });
  } catch (error) {
    console.error('[STOK_KELUAR_GET]', error);
    return new NextResponse('Internal error', { status: 500 });
  }
} 
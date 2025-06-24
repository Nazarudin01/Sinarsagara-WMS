import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { nomor, tanggal, gudangId, penanggungJawab, items } = body;
    if (!nomor || !tanggal || !gudangId || !penanggungJawab || !items || !Array.isArray(items)) {
      return NextResponse.json({ error: "Data tidak lengkap" }, { status: 400 });
    }

    // Simpan opname dan detail dalam transaksi
    const result = await prisma.$transaction(async (tx) => {
      // 1. Simpan header opname
      const opname = await tx.stokOpname.create({
        data: {
          nomor,
          tanggal: new Date(tanggal),
          gudang: gudangId,
          keterangan: penanggungJawab,
        },
      });

      // 2. Simpan detail opname dan update stok
      for (const item of items) {
        // Simpan detail
        await tx.stokOpnameDetail.create({
          data: {
            opnameId: opname.id,
            barangId: item.barangId || item.id, // id barang
            stokSebelum: item.stok,
            stokAktual: item.stokAktual,
            selisih: item.selisih,
            satuan: item.satuan,
          },
        });
        // Update stokGudang
        await tx.stokGudang.update({
          where: { id: item.id },
          data: { stok: item.stokAktual },
        });
      }
      return opname;
    });

    return NextResponse.json({ data: result });
  } catch (error) {
    console.error("[OPNAME_POST]", error);
    return NextResponse.json({ error: "Gagal menyimpan opname" }, { status: 500 });
  }
}

export async function GET() {
  try {
    const opnames = await prisma.stokOpname.findMany({
      orderBy: { tanggal: "desc" },
      include: { details: true },
    });
    // Ambil nama gudang
    const gudangList = await prisma.gudang.findMany({ select: { id: true, nama: true } });
    const gudangMap = Object.fromEntries(gudangList.map(g => [g.id, g.nama]));
    // Untuk setiap opname, ambil total stok sebelum dan sesudah opname dari detail
    const data = opnames.map((item) => {
      const jumlahStok = item.details.reduce((sum, d) => sum + (d.stokSebelum || 0), 0);
      const jumlahStokAktual = item.details.reduce((sum, d) => sum + (d.stokAktual || 0), 0);
      return {
        id: item.id,
        nomor: item.nomor,
        tanggal: item.tanggal.toISOString().slice(0, 10),
        gudang: gudangMap[item.gudang] || '-',
        jumlahStok,
        jumlahStokAktual,
        penanggungJawab: item.keterangan || '-',
      };
    });
    return NextResponse.json({ data });
  } catch (error) {
    console.error("[OPNAME_GET]", error);
    return NextResponse.json({ error: "Gagal mengambil data opname" }, { status: 500 });
  }
}

export async function DELETE(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");
    if (!id) return NextResponse.json({ error: "ID opname diperlukan" }, { status: 400 });

    await prisma.$transaction(async (tx) => {
      // Ambil semua detail opname
      const details = await tx.stokOpnameDetail.findMany({ where: { opnameId: id } });
      // Rollback stok barang
      for (const detail of details) {
        // Cari stokGudang yang sesuai
        const stokGudang = await tx.stokGudang.findFirst({
          where: {
            barangId: detail.barangId,
            gudangId: (await tx.stokOpname.findUnique({ where: { id } }))?.gudang,
          },
        });
        if (stokGudang) {
          await tx.stokGudang.update({
            where: { id: stokGudang.id },
            data: { stok: detail.stokSebelum },
          });
        }
      }
      // Hapus detail
      await tx.stokOpnameDetail.deleteMany({ where: { opnameId: id } });
      // Hapus header
      await tx.stokOpname.delete({ where: { id } });
    });
    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("[OPNAME_DELETE]", error);
    return NextResponse.json({ error: "Gagal menghapus opname" }, { status: 500 });
  }
} 
import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const gudangId = searchParams.get("gudangId");
    const rentang = searchParams.get("rentang") || "harian";
    const tanggal = searchParams.get("tanggal");
    const minggu = searchParams.get("minggu");
    const bulan = searchParams.get("bulan");

    if (!gudangId) {
      return NextResponse.json({ error: "gudangId diperlukan" }, { status: 400 });
    }

    // Tentukan range waktu
    let startDate: Date, endDate: Date;
    const now = new Date();
    if (rentang === "harian" && tanggal) {
      startDate = new Date(tanggal);
      endDate = new Date(tanggal);
      endDate.setHours(23,59,59,999);
    } else if (rentang === "mingguan" && minggu) {
      // minggu format: yyyy-Wxx
      const [year, week] = minggu.split("-W");
      const firstDay = new Date(Number(year), 0, 1 + (Number(week) - 1) * 7);
      const dayOfWeek = firstDay.getDay();
      startDate = new Date(firstDay);
      if (dayOfWeek <= 4) startDate.setDate(firstDay.getDate() - firstDay.getDay() + 1);
      else startDate.setDate(firstDay.getDate() + 8 - firstDay.getDay());
      endDate = new Date(startDate);
      endDate.setDate(startDate.getDate() + 6);
      endDate.setHours(23,59,59,999);
    } else if (rentang === "bulanan" && bulan) {
      // bulan format: yyyy-MM
      const [year, month] = bulan.split("-");
      startDate = new Date(Number(year), Number(month) - 1, 1);
      endDate = new Date(Number(year), Number(month), 0, 23, 59, 59, 999);
    } else {
      // Default: hari ini
      startDate = new Date(now.toISOString().slice(0,10));
      endDate = new Date(now.toISOString().slice(0,10));
      endDate.setHours(23,59,59,999);
    }

    // Ambil stokGudang di gudang
    const stokGudang = await prisma.stokGudang.findMany({
      where: { gudangId },
      include: {
        barang: true,
        kodeRak: true,
      },
    });

    const stokGudangIds = stokGudang.map(sg => sg.id);
    if (stokGudangIds.length === 0) {
      return NextResponse.json({ data: [] });
    }

    // Ambil transaksi masuk
    const masuk = await prisma.stokMasukItem.findMany({
      where: {
        stokGudangId: { in: stokGudangIds },
        stokMasuk: {
          tanggal: { gte: startDate, lte: endDate },
        },
      },
      include: { stokGudang: true },
    });
    // Ambil transaksi keluar pakai TransaksiKeluarDetail
    const keluar = await prisma.transaksiKeluarDetail.findMany({
      where: {
        barangId: { in: stokGudang.map(sg => sg.barangId) },
        transaksiKeluar: {
          tanggal: { gte: startDate, lte: endDate },
          gudangId: gudangId,
        },
      },
      include: { transaksiKeluar: true },
    });
    // Ambil opname
    const opname = await prisma.stokOpnameDetail.findMany({
      where: {
        barangId: { in: stokGudang.map(sg => sg.barangId) },
        opname: {
          tanggal: { gte: startDate, lte: endDate },
          gudang: gudangId,
        },
      },
      include: { opname: true, barang: true },
    });

    // Map data
    const result = stokGudang.map((sg) => {
      const masukQty = masuk.filter(m => m.stokGudangId === sg.id).reduce((a, b) => a + (b.qty || 0), 0);
      // KeluarQty: jumlahkan semua transaksiKeluarDetail untuk barangId ini
      const keluarQty = keluar.filter(k => k.barangId === sg.barangId).reduce((a, b) => a + (b.qty || 0), 0);
      // Opname: ambil selisih terakhir di periode
      const opnameData = opname.filter(o => o.barangId === sg.barangId).sort((a, b) => b.opname.tanggal.getTime() - a.opname.tanggal.getTime());
      const opnameSelisih = opnameData.length > 0 ? opnameData[0].selisih : 0;
      // Stok akhir = stok sekarang
      const stokAkhir = sg.stok;
      // Stok awal = stok akhir - masuk + keluar - opname
      const stokAwal = stokAkhir - masukQty + keluarQty - opnameSelisih;
      // Perbaiki path gambar
      let gambar = sg.barang.gambar;
      if (!gambar || gambar === "") {
        gambar = "/default-image.png";
      } else if (!gambar.startsWith("http")) {
        gambar = `/uploads/${gambar}`;
      }
      return {
        gambar,
        rak: sg.kodeRak?.kode || "-",
        sku: sg.barang.sku,
        nama: sg.barang.nama,
        satuan: sg.barang.satuan,
        jenis: sg.barang.jenis,
        stokAwal,
        masuk: masukQty,
        keluar: keluarQty,
        opname: opnameSelisih,
        stokAkhir,
      };
    });

    return NextResponse.json({ data: result });
  } catch (error) {
    console.error("[LAPORAN_STOK_GET]", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
} 
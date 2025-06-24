import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import * as XLSX from "xlsx";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const gudangId = searchParams.get("gudangId");
    const rentang = searchParams.get("rentang") || "harian";
    const tanggal = searchParams.get("tanggal");
    const minggu = searchParams.get("minggu");
    const bulan = searchParams.get("bulan");
    const type = searchParams.get("type") || "excel";

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
      const [year, month] = bulan.split("-");
      startDate = new Date(Number(year), Number(month) - 1, 1);
      endDate = new Date(Number(year), Number(month), 0, 23, 59, 59, 999);
    } else {
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

    // Ambil transaksi masuk, keluar, opname di periode
    const masuk = await prisma.stokMasukItem.findMany({
      where: {
        stokGudang: { gudangId },
        stokMasuk: {
          tanggal: { gte: startDate, lte: endDate },
        },
      },
      include: { stokGudang: true },
    });
    const keluar = await prisma.transaksiKeluarDetail.findMany({
      where: {
        barang: { stokGudang: { some: { gudangId } } },
        transaksiKeluar: {
          tanggal: { gte: startDate, lte: endDate },
        },
      },
      include: { transaksiKeluar: true, barang: true },
    });
    const opname = await prisma.stokOpnameDetail.findMany({
      where: {
        barang: { stokGudang: { some: { gudangId } } },
        opname: {
          tanggal: { gte: startDate, lte: endDate },
        },
      },
      include: { opname: true, barang: true },
    });

    // Map data
    const result = stokGudang.map((sg, idx) => {
      const masukQty = masuk.filter(m => m.stokGudangId === sg.id).reduce((a, b) => a + (b.qty || 0), 0);
      const keluarQty = keluar.filter(k => k.barangId === sg.barangId).reduce((a, b) => a + (b.qty || 0), 0);
      const opnameData = opname.filter(o => o.barangId === sg.barangId).sort((a, b) => b.opname.tanggal.getTime() - a.opname.tanggal.getTime());
      const opnameSelisih = opnameData.length > 0 ? opnameData[0].selisih : 0;
      const stokAkhir = sg.stok;
      const stokAwal = stokAkhir - masukQty + keluarQty - opnameSelisih;
      return {
        No: idx + 1,
        Gambar: sg.barang.gambar || "",
        Rak: sg.kodeRak?.kode || "-",
        SKU: sg.barang.sku,
        "Nama Barang": sg.barang.nama,
        Satuan: sg.barang.satuan,
        Jenis: sg.barang.jenis,
        "Stok Awal": stokAwal,
        Masuk: masukQty,
        Keluar: keluarQty,
        Opname: opnameSelisih,
        "Stok Akhir": stokAkhir,
      };
    });

    // 3. 10 Barang Stok Terbanyak
    const barangStok = await prisma.barang.findMany({ include: { stokGudang: true } });
    const barangStokSorted = barangStok
      .map(b => ({
        ...b,
        totalStok: b.stokGudang.reduce((sum, sg) => sum + sg.stok, 0),
      }))
      .sort((a, b) => b.totalStok - a.totalStok)
      .slice(0, 10);
    const barangStokLabels = barangStokSorted.map(b => b.nama);
    const barangStokData = barangStokSorted.map(b => b.totalStok);

    // Generate file
    if (type === "csv") {
      const ws = XLSX.utils.json_to_sheet(result);
      const csv = XLSX.utils.sheet_to_csv(ws);
      return new NextResponse(csv, {
        status: 200,
        headers: {
          'Content-Disposition': `attachment; filename="laporan-stok.csv"`,
          'Content-Type': 'text/csv',
        },
      });
    } else {
      const ws = XLSX.utils.json_to_sheet(result);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Laporan Stok');
      const buffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
      return new NextResponse(buffer, {
        status: 200,
        headers: {
          'Content-Disposition': `attachment; filename="laporan-stok.xlsx"`,
          'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        },
      });
    }
  } catch (error) {
    console.error("[LAPORAN_STOK_EXPORT]", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
} 
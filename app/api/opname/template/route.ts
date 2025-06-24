import { NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { write, utils } from "xlsx";

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const gudangId = searchParams.get("gudangId");
    const format = searchParams.get("format") || "excel";
    if (!gudangId) return NextResponse.json({ error: "GudangId diperlukan" }, { status: 400 });

    // Fetch barang di gudang
    const stokGudang = await prisma.stokGudang.findMany({
      where: { gudangId },
      include: { barang: true, kodeRak: true },
      orderBy: { nama: "asc" },
    });

    // Baris 1: Tanggal
    // Baris 2: Penanggung Jawab
    // Baris 4: Header
    // Baris 5 dst: Data
    const rows = [];
    rows.push(["Tanggal *", "", "", "", "", "", "", ""]);
    rows.push(["Penanggung Jawab *", "", "", "", "", "", "", ""]);
    rows.push([]); // Baris kosong
    rows.push([
      "Kode Rak",
      "SKU",
      "Nama Barang",
      "Stok",
      "Stok Aktual *",
      "Selisih (auto)",
      "Satuan",
    ]);
    for (const item of stokGudang) {
      rows.push([
        item.kodeRak?.kode || "-",
        item.barang.sku,
        item.barang.nama,
        item.stok,
        "", // Stok Aktual (user isi)
        "", // Selisih (auto di backend/import)
        item.barang.satuan,
      ]);
    }

    if (format === "csv") {
      // CSV
      const csv = rows.map(r => r.map(v => `"${v}"`).join(",")).join("\r\n");
      return new Response(csv, {
        headers: {
          "Content-Type": "text/csv",
          "Content-Disposition": `attachment; filename=template-opname.csv`,
        },
      });
    } else {
      // Excel
      const ws = utils.aoa_to_sheet(rows);
      const wb = utils.book_new();
      utils.book_append_sheet(wb, ws, "Opname");
      const buf = write(wb, { type: "buffer", bookType: "xlsx" });
      return new Response(buf, {
        headers: {
          "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
          "Content-Disposition": `attachment; filename=template-opname.xlsx`,
        },
      });
    }
  } catch (error) {
    console.error("[OPNAME_TEMPLATE]", error);
    return NextResponse.json({ error: "Gagal generate template" }, { status: 500 });
  }
} 
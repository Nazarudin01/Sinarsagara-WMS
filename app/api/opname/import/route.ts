import { NextRequest, NextResponse } from "next/server";
import prisma from "@/lib/prisma";
import { read, utils } from "xlsx";

export async function POST(request: NextRequest) {
  try {
    // Ambil file dari formData
    const formData = await request.formData();
    const file = formData.get("file");
    if (!file || !(file instanceof Blob)) {
      return NextResponse.json({ error: "No file uploaded" }, { status: 400 });
    }
    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    const workbook = read(buffer, { type: "buffer" });
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const rows = utils.sheet_to_json(sheet, { header: 1 });

    // Baris 1: Tanggal, Baris 2: Penanggung Jawab
    let tanggalRaw = rows[0]?.[0];
    let penanggungJawab = rows[1]?.[0];
    if (!tanggalRaw || !penanggungJawab) {
      return NextResponse.json({ error: "Tanggal dan Penanggung Jawab wajib diisi" }, { status: 400 });
    }

    // Parsing tanggal lebih robust
    let tanggal = null;
    if (typeof tanggalRaw === "number") {
      // Excel date serial number
      tanggal = new Date(Math.round((tanggalRaw - 25569) * 86400 * 1000));
    } else if (typeof tanggalRaw === "string") {
      // Hilangkan label jika ada, misal: "Tanggal *: 2024-06-25"
      const match = tanggalRaw.match(/(\d{4}-\d{2}-\d{2}|\d{2}[\/\-]\d{2}[\/\-]\d{4})/);
      if (match) {
        // Format ISO atau dd/MM/yyyy
        const val = match[1];
        if (/\d{4}-\d{2}-\d{2}/.test(val)) {
          tanggal = new Date(val);
        } else if (/\d{2}[\/\-]\d{2}[\/\-]\d{4}/.test(val)) {
          // dd/MM/yyyy atau dd-MM-yyyy
          const [d, m, y] = val.split(/[\/\-]/);
          tanggal = new Date(`${y}-${m}-${d}`);
        }
      }
    }
    if (!tanggal || isNaN(tanggal.getTime())) {
      return NextResponse.json({ error: "Format tanggal tidak valid" }, { status: 400 });
    }

    // Baris 4: Header, Baris 5 dst: Data
    const dataRows = rows.slice(4).filter(r => r[1]); // SKU harus ada
    if (dataRows.length === 0) {
      return NextResponse.json({ error: "Tidak ada data barang" }, { status: 400 });
    }
    // Ambil gudangId dari request (atau bisa dari SKU/kodeRak jika perlu)
    // Untuk demo, asumsikan dari SKU pertama
    const sku = dataRows[0][1];
    const stokGudang = await prisma.stokGudang.findFirst({ where: { sku } });
    const gudangId = stokGudang?.gudangId;
    if (!gudangId) return NextResponse.json({ error: "Gudang tidak ditemukan" }, { status: 400 });

    // Generate nomor opname
    const now = new Date();
    const month = String(now.getMonth() + 1).padStart(2, "0");
    const year = String(now.getFullYear()).slice(-2);
    const prefix = `OPN-${month}${year}-`;
    const lastOpname = await prisma.stokOpname.findFirst({
      where: { nomor: { startsWith: prefix } },
      orderBy: { nomor: "desc" },
      select: { nomor: true },
    });
    let newSequence = 1;
    if (lastOpname) {
      const lastSequence = parseInt(lastOpname.nomor.split("-")[2], 10);
      newSequence = lastSequence + 1;
    }
    const nomor = `${prefix}${newSequence.toString().padStart(3, "0")}`;

    // Simpan opname dan detail
    const result = await prisma.$transaction(async (tx) => {
      const opname = await tx.stokOpname.create({
        data: {
          nomor,
          tanggal: tanggal,
          gudang: gudangId,
          keterangan: penanggungJawab,
        },
      });
      for (const row of dataRows) {
        const [kodeRak, sku, nama, stok, stokAktual, , satuan] = row;
        if (!sku || stokAktual === undefined || stokAktual === "") continue;
        const barang = await tx.barang.findFirst({ where: { sku } });
        if (!barang) continue;
        const stokGudang = await tx.stokGudang.findFirst({ where: { sku, gudangId } });
        if (!stokGudang) continue;
        const stokSebelum = Number(stokGudang.stok);
        const stokAktualNum = Number(stokAktual);
        const selisih = stokAktualNum - stokSebelum;
        await tx.stokOpnameDetail.create({
          data: {
            opnameId: opname.id,
            barangId: barang.id,
            stokSebelum,
            stokAktual: stokAktualNum,
            selisih,
            satuan: satuan || barang.satuan,
          },
        });
        // Update stokGudang
        await tx.stokGudang.update({ where: { id: stokGudang.id }, data: { stok: stokAktualNum } });
      }
      return opname;
    });
    return NextResponse.json({ data: result });
  } catch (error) {
    console.error("[OPNAME_IMPORT]", error);
    return NextResponse.json({ error: "Gagal import opname" }, { status: 500 });
  }
} 
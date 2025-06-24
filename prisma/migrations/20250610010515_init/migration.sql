-- CreateEnum
CREATE TYPE "Role" AS ENUM ('ADMIN', 'MANAGER', 'USER');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT,
    "password" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'USER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "isActive" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Gudang" (
    "id" TEXT NOT NULL,
    "kode" TEXT NOT NULL,
    "nama" TEXT NOT NULL,
    "kategori" TEXT NOT NULL,
    "alamat" TEXT NOT NULL,
    "jumlahBarang" INTEGER NOT NULL DEFAULT 0,
    "jumlahStok" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Gudang_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Barang" (
    "id" TEXT NOT NULL,
    "sku" TEXT NOT NULL,
    "nama" TEXT NOT NULL,
    "kategori" TEXT NOT NULL,
    "satuan" TEXT NOT NULL,
    "hargaBeli" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "stok" INTEGER NOT NULL DEFAULT 0,
    "gambar" TEXT,
    "jenis" TEXT,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Barang_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Pemasok" (
    "id" TEXT NOT NULL,
    "kode" TEXT NOT NULL,
    "nama" TEXT NOT NULL,
    "alamat" TEXT NOT NULL,
    "telepon" TEXT NOT NULL,
    "email" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Pemasok_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Pelanggan" (
    "id" TEXT NOT NULL,
    "kode" TEXT NOT NULL,
    "nama" TEXT NOT NULL,
    "alamat" TEXT NOT NULL,
    "telepon" TEXT NOT NULL,
    "email" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Pelanggan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "StokMasuk" (
    "id" TEXT NOT NULL,
    "nomor" TEXT NOT NULL,
    "tanggal" TIMESTAMP(3) NOT NULL,
    "pemasok" TEXT NOT NULL,
    "gudang" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "total" DOUBLE PRECISION NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "StokMasuk_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "StokMasukItem" (
    "id" TEXT NOT NULL,
    "sku" TEXT NOT NULL,
    "nama_barang" TEXT NOT NULL,
    "qty" INTEGER NOT NULL,
    "harga" DOUBLE PRECISION NOT NULL,
    "stokMasukId" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "StokMasukItem_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LoginLog" (
    "id" TEXT NOT NULL,
    "userId" TEXT,
    "email" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "errorMessage" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LoginLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TransaksiMasuk" (
    "id" TEXT NOT NULL,
    "nomor" TEXT NOT NULL,
    "tanggal" TIMESTAMP(3) NOT NULL,
    "pemasok" TEXT NOT NULL,
    "gudang" TEXT NOT NULL,
    "total" DOUBLE PRECISION NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TransaksiMasuk_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TransaksiMasukDetail" (
    "id" TEXT NOT NULL,
    "transaksiMasukId" TEXT NOT NULL,
    "barangId" TEXT NOT NULL,
    "qty" INTEGER NOT NULL,
    "harga" DOUBLE PRECISION NOT NULL,

    CONSTRAINT "TransaksiMasukDetail_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TransaksiKeluar" (
    "id" TEXT NOT NULL,
    "nomor" TEXT NOT NULL,
    "tanggal" TIMESTAMP(3) NOT NULL,
    "pelanggan" TEXT NOT NULL,
    "gudang" TEXT NOT NULL,
    "total" DOUBLE PRECISION NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TransaksiKeluar_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TransaksiKeluarDetail" (
    "id" TEXT NOT NULL,
    "transaksiKeluarId" TEXT NOT NULL,
    "barangId" TEXT NOT NULL,
    "qty" INTEGER NOT NULL,
    "harga" DOUBLE PRECISION NOT NULL,

    CONSTRAINT "TransaksiKeluarDetail_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "StokGudang" (
    "id" TEXT NOT NULL,
    "sku" TEXT NOT NULL,
    "nama" TEXT NOT NULL,
    "gudangId" TEXT NOT NULL,
    "barangId" TEXT NOT NULL,
    "stok" INTEGER NOT NULL,
    "kodeRakId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "StokGudang_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "StokOpname" (
    "id" TEXT NOT NULL,
    "nomor" TEXT NOT NULL,
    "tanggal" TIMESTAMP(3) NOT NULL,
    "gudang" TEXT NOT NULL,
    "keterangan" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "StokOpname_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "KodeRak" (
    "id" TEXT NOT NULL,
    "kode" TEXT NOT NULL,
    "nama" TEXT NOT NULL,
    "kategori" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "KodeRak_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "Gudang_kode_key" ON "Gudang"("kode");

-- CreateIndex
CREATE UNIQUE INDEX "Barang_sku_key" ON "Barang"("sku");

-- CreateIndex
CREATE UNIQUE INDEX "Pemasok_kode_key" ON "Pemasok"("kode");

-- CreateIndex
CREATE UNIQUE INDEX "Pelanggan_kode_key" ON "Pelanggan"("kode");

-- CreateIndex
CREATE UNIQUE INDEX "StokMasuk_nomor_key" ON "StokMasuk"("nomor");

-- CreateIndex
CREATE UNIQUE INDEX "TransaksiMasuk_nomor_key" ON "TransaksiMasuk"("nomor");

-- CreateIndex
CREATE UNIQUE INDEX "TransaksiKeluar_nomor_key" ON "TransaksiKeluar"("nomor");

-- CreateIndex
CREATE UNIQUE INDEX "StokGudang_barangId_gudangId_key" ON "StokGudang"("barangId", "gudangId");

-- CreateIndex
CREATE UNIQUE INDEX "StokOpname_nomor_key" ON "StokOpname"("nomor");

-- CreateIndex
CREATE UNIQUE INDEX "KodeRak_kode_key" ON "KodeRak"("kode");

-- AddForeignKey
ALTER TABLE "StokMasukItem" ADD CONSTRAINT "StokMasukItem_stokMasukId_fkey" FOREIGN KEY ("stokMasukId") REFERENCES "StokMasuk"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LoginLog" ADD CONSTRAINT "LoginLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TransaksiMasukDetail" ADD CONSTRAINT "TransaksiMasukDetail_transaksiMasukId_fkey" FOREIGN KEY ("transaksiMasukId") REFERENCES "TransaksiMasuk"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TransaksiMasukDetail" ADD CONSTRAINT "TransaksiMasukDetail_barangId_fkey" FOREIGN KEY ("barangId") REFERENCES "Barang"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TransaksiKeluarDetail" ADD CONSTRAINT "TransaksiKeluarDetail_transaksiKeluarId_fkey" FOREIGN KEY ("transaksiKeluarId") REFERENCES "TransaksiKeluar"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TransaksiKeluarDetail" ADD CONSTRAINT "TransaksiKeluarDetail_barangId_fkey" FOREIGN KEY ("barangId") REFERENCES "Barang"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "StokGudang" ADD CONSTRAINT "StokGudang_barangId_fkey" FOREIGN KEY ("barangId") REFERENCES "Barang"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "StokGudang" ADD CONSTRAINT "StokGudang_gudangId_fkey" FOREIGN KEY ("gudangId") REFERENCES "Gudang"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "StokGudang" ADD CONSTRAINT "StokGudang_kodeRakId_fkey" FOREIGN KEY ("kodeRakId") REFERENCES "KodeRak"("id") ON DELETE SET NULL ON UPDATE CASCADE;

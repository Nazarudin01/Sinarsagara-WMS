-- CreateTable
CREATE TABLE "StokOpnameDetail" (
    "id" TEXT NOT NULL,
    "opnameId" TEXT NOT NULL,
    "barangId" TEXT NOT NULL,
    "stokSebelum" INTEGER NOT NULL,
    "stokAktual" INTEGER NOT NULL,
    "selisih" INTEGER NOT NULL,
    "satuan" TEXT NOT NULL,

    CONSTRAINT "StokOpnameDetail_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "StokOpnameDetail" ADD CONSTRAINT "StokOpnameDetail_opnameId_fkey" FOREIGN KEY ("opnameId") REFERENCES "StokOpname"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "StokOpnameDetail" ADD CONSTRAINT "StokOpnameDetail_barangId_fkey" FOREIGN KEY ("barangId") REFERENCES "Barang"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

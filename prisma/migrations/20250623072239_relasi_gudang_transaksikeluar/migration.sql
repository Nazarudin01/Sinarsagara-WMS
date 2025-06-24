/*
  Warnings:

  - You are about to drop the column `gudang` on the `TransaksiKeluar` table. All the data in the column will be lost.
  - Added the required column `gudangId` to the `TransaksiKeluar` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "StokMasukItem" ADD COLUMN     "kodeRakId" TEXT,
ADD COLUMN     "stokGudangId" TEXT;

-- AlterTable
ALTER TABLE "TransaksiKeluar" DROP COLUMN "gudang",
ADD COLUMN     "gudangId" TEXT NOT NULL;

-- AddForeignKey
ALTER TABLE "StokMasukItem" ADD CONSTRAINT "StokMasukItem_kodeRakId_fkey" FOREIGN KEY ("kodeRakId") REFERENCES "KodeRak"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "StokMasukItem" ADD CONSTRAINT "StokMasukItem_stokGudangId_fkey" FOREIGN KEY ("stokGudangId") REFERENCES "StokGudang"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "TransaksiKeluar" ADD CONSTRAINT "TransaksiKeluar_gudangId_fkey" FOREIGN KEY ("gudangId") REFERENCES "Gudang"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

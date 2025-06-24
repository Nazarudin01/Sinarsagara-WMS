/*
  Warnings:

  - A unique constraint covering the columns `[barangId,gudangId,kodeRakId]` on the table `StokGudang` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX "StokGudang_barangId_gudangId_key";

-- CreateIndex
CREATE UNIQUE INDEX "StokGudang_barangId_gudangId_kodeRakId_key" ON "StokGudang"("barangId", "gudangId", "kodeRakId");

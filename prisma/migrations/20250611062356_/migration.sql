/*
  Warnings:

  - You are about to drop the column `isActive` on the `Barang` table. All the data in the column will be lost.
  - You are about to drop the column `stok` on the `Barang` table. All the data in the column will be lost.
  - Made the column `jenis` on table `Barang` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "Barang" DROP COLUMN "isActive",
DROP COLUMN "stok",
ALTER COLUMN "hargaBeli" DROP DEFAULT,
ALTER COLUMN "jenis" SET NOT NULL;

-- CreateTable
CREATE TABLE "Stok" (
    "id" TEXT NOT NULL,
    "barangId" TEXT NOT NULL,
    "rakId" TEXT NOT NULL,
    "jumlah" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Stok_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Stok_barangId_idx" ON "Stok"("barangId");

-- CreateIndex
CREATE INDEX "Stok_rakId_idx" ON "Stok"("rakId");

-- AddForeignKey
ALTER TABLE "Stok" ADD CONSTRAINT "Stok_barangId_fkey" FOREIGN KEY ("barangId") REFERENCES "Barang"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Stok" ADD CONSTRAINT "Stok_rakId_fkey" FOREIGN KEY ("rakId") REFERENCES "Rak"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

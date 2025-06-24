/*
  Warnings:

  - You are about to drop the column `pelanggan` on the `TransaksiKeluar` table. All the data in the column will be lost.
  - Added the required column `pelangganId` to the `TransaksiKeluar` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "TransaksiKeluar" DROP COLUMN "pelanggan",
ADD COLUMN     "pelangganId" TEXT NOT NULL;

-- AddForeignKey
ALTER TABLE "TransaksiKeluar" ADD CONSTRAINT "TransaksiKeluar_pelangganId_fkey" FOREIGN KEY ("pelangganId") REFERENCES "Pelanggan"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

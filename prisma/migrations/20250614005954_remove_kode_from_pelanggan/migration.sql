/*
  Warnings:

  - You are about to drop the column `kode` on the `Pelanggan` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "Pelanggan_kode_key";

-- AlterTable
ALTER TABLE "Pelanggan" DROP COLUMN "kode";

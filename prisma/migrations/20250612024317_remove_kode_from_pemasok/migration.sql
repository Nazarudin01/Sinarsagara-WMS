/*
  Warnings:

  - You are about to drop the column `kode` on the `Pemasok` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "Pemasok_kode_key";

-- AlterTable
ALTER TABLE "Pemasok" DROP COLUMN "kode";

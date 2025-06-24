-- CreateTable
CREATE TABLE "Rak" (
    "id" TEXT NOT NULL,
    "kode" TEXT NOT NULL,
    "keterangan" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Rak_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Rak_kode_key" ON "Rak"("kode"); 
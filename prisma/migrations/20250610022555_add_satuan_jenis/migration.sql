-- CreateTable
CREATE TABLE "Satuan" (
    "id" TEXT NOT NULL,
    "nama" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Satuan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Jenis" (
    "id" TEXT NOT NULL,
    "nama" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Jenis_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "Satuan_nama_key" ON "Satuan"("nama");

-- CreateIndex
CREATE UNIQUE INDEX "Jenis_nama_key" ON "Jenis"("nama");

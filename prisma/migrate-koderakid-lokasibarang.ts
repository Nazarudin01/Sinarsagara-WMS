import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  const stokList = await prisma.stokGudang.findMany({
    where: {
      kodeRakId: null,
    },
  });

  let updated = 0;
  for (const stok of stokList) {
    // Cari KodeRak berdasarkan SKU barang
    const kodeRak = await prisma.kodeRak.findFirst({
      where: { 
        kode: stok.sku 
      },
    });
    
    if (kodeRak) {
      await prisma.stokGudang.update({
        where: { id: stok.id },
        data: { kodeRakId: kodeRak.id },
      });
      updated++;
    }
  }
  console.log(`Migrasi selesai. Total stokGudang yang diupdate: ${updated}`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  }); 
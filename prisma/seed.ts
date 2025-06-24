import { PrismaClient } from '@prisma/client';
const { hash } = require('bcrypt');

const prisma = new PrismaClient();

async function main() {
  // Seed Satuan
  const satuanList = ['PCS', 'BOX', 'PACK', 'KG', 'LITER'];
  for (const nama of satuanList) {
    await prisma.satuan.upsert({
      where: { nama },
      update: {},
      create: { nama }
    });
  }

  // Seed Jenis
  const jenisList = ['BAHAN BAKU', 'BARANG JADI', 'KEMASAN', 'SPAREPART'];
  for (const nama of jenisList) {
    await prisma.jenis.upsert({
      where: { nama },
      update: {},
      create: { nama }
    });
  }

  // Seed Pemasok
  const pemasokList = [
    { nama: 'PT Supplier Utama', alamat: 'Jakarta', telepon: '021-1234567' },
    { nama: 'CV Distributor Jaya', alamat: 'Bandung', telepon: '022-7654321' },
    { nama: 'UD Toko Makmur', alamat: 'Surabaya', telepon: '031-9876543' }
  ];
  for (const pemasok of pemasokList) {
    await prisma.pemasok.upsert({
      where: { id: pemasok.nama }, // Gunakan nama sebagai id sementara
      update: {},
      create: pemasok
    });
  }

  // Seed Gudang
  const gudangList = [
    { kode: 'GD001', nama: 'Gudang Utama', alamat: 'Jakarta Pusat', kategori: 'BAHAN_BAKU' },
    { kode: 'GD002', nama: 'Gudang Produksi', alamat: 'Jakarta Selatan', kategori: 'BARANG_SETENGAH_JADI' },
    { kode: 'GD003', nama: 'Gudang Distribusi', alamat: 'Jakarta Barat', kategori: 'BARANG_JADI' }
  ];
  for (const gudang of gudangList) {
    await prisma.gudang.upsert({
      where: { kode: gudang.kode },
      update: {},
      create: gudang
    });
  }

  // Seed Kode Rak
  const rakList = [
    { kode: 'RK001', nama: 'Rak A-01', kategori: 'BAHAN_BAKU' },
    { kode: 'RK002', nama: 'Rak A-02', kategori: 'BAHAN_BAKU' },
    { kode: 'RK003', nama: 'Rak B-01', kategori: 'BARANG_SETENGAH_JADI' },
    { kode: 'RK004', nama: 'Rak B-02', kategori: 'BARANG_SETENGAH_JADI' },
    { kode: 'RK005', nama: 'Rak C-01', kategori: 'BARANG_JADI' },
    { kode: 'RK006', nama: 'Rak C-02', kategori: 'BARANG_JADI' }
  ];
  for (const rak of rakList) {
    await prisma.kodeRak.upsert({
      where: { kode: rak.kode },
      update: {},
      create: rak
    });
  }

  // Seed Barang
  const barangList = [
    { 
      sku: 'BB001', 
      nama: 'Bahan Baku 1', 
      kategori: 'BAHAN_BAKU',
      jenis: 'BAHAN BAKU',
      satuan: 'KG',
      hargaBeli: 50000
    },
    { 
      sku: 'BB002', 
      nama: 'Bahan Baku 2', 
      kategori: 'BAHAN_BAKU',
      jenis: 'BAHAN BAKU',
      satuan: 'PCS',
      hargaBeli: 25000
    },
    { 
      sku: 'BSJ001', 
      nama: 'Barang Setengah Jadi 1', 
      kategori: 'BARANG_SETENGAH_JADI',
      jenis: 'BARANG JADI',
      satuan: 'BOX',
      hargaBeli: 100000
    },
    { 
      sku: 'BSJ002', 
      nama: 'Barang Setengah Jadi 2', 
      kategori: 'BARANG_SETENGAH_JADI',
      jenis: 'BARANG JADI',
      satuan: 'PACK',
      hargaBeli: 75000
    },
    { 
      sku: 'BJ001', 
      nama: 'Barang Jadi 1', 
      kategori: 'BARANG_JADI',
      jenis: 'BARANG JADI',
      satuan: 'PCS',
      hargaBeli: 200000
    },
    { 
      sku: 'BJ002', 
      nama: 'Barang Jadi 2', 
      kategori: 'BARANG_JADI',
      jenis: 'BARANG JADI',
      satuan: 'BOX',
      hargaBeli: 150000
    }
  ];
  for (const barang of barangList) {
    await prisma.barang.upsert({
      where: { sku: barang.sku },
      update: {},
      create: barang
    });
  }

  const password = await hash('password123', 12);
  const user = await prisma.user.upsert({
    where: { email: 'admin@example.com' },
    update: {},
    create: {
      email: 'admin@example.com',
      name: 'Admin',
      password,
      role: 'ADMIN',
    },
  });
  console.log({ user });

  console.log('Seed data berhasil ditambahkan');
}

main()
  .then(() => prisma.$disconnect())
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  }); 
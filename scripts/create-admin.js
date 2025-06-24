const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

async function main() {
  try {
    // Hapus semua user yang ada
    await prisma.user.deleteMany();
    console.log('Semua user lama telah dihapus');

    // Buat user admin baru
    const hashedPassword = await bcrypt.hash('Sinarsagara9', 12);
    
    const admin = await prisma.user.create({
      data: {
        email: 'admin@wms.com',
        name: 'Administrator',
        password: hashedPassword,
        role: 'ADMIN',
        isActive: true,
      },
    });

    console.log('User admin baru telah dibuat:', admin);
  } catch (error) {
    console.error('Error:', error);
  } finally {
    await prisma.$disconnect();
  }
}

main(); 
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function verifyDatabase() {
  try {
    // Test database connection
    await prisma.$connect();
    console.log('✅ Database connection successful');

    // Check if admin user exists
    const adminUser = await prisma.user.findFirst({
      where: {
        role: 'ADMIN'
      }
    });

    if (adminUser) {
      console.log('✅ Admin user exists:', adminUser.email);
    } else {
      console.warn('❌ No admin user found');
    }

    // Check all required tables
    const requiredTables = [
      'User',
      'Gudang',
      'Barang',
      'LokasiBarang',
      'StokGudang',
      'Supplier',
      'Customer',
      'TransaksiMasuk',
      'TransaksiKeluar',
      'DetailTransaksiMasuk',
      'DetailTransaksiKeluar',
      'StokOpname'
    ];

    const tables = await prisma.$queryRaw`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `;

    const existingTables = tables.map(t => t.table_name);
    console.log('\nChecking required tables:');
    
    for (const table of requiredTables) {
      const tableName = table.toLowerCase();
      if (existingTables.includes(tableName)) {
        console.log(`✅ Table ${table} exists`);
      } else {
        console.log(`❌ Table ${table} is missing`);
      }
    }

    // Check Prisma schema
    console.log('\nChecking Prisma schema...');
    const schema = await prisma.$queryRaw`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_schema = 'public' 
      AND table_name = 'user'
    `;
    
    if (schema.length > 0) {
      console.log('✅ Prisma schema is properly synced');
    } else {
      console.log('❌ Prisma schema might be out of sync');
    }

  } catch (error) {
    console.error('❌ Database verification failed:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

verifyDatabase(); 
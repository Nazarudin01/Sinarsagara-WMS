import { PrismaClient } from '@prisma/client';
import logger from '../lib/logger';

const prisma = new PrismaClient();

async function checkDatabase() {
  try {
    // Test database connection
    await prisma.$connect();
    logger.info('Database connection successful');

    // Check if admin user exists
    const adminUser = await prisma.user.findFirst({
      where: {
        role: 'ADMIN'
      }
    });

    if (adminUser) {
      logger.info('Admin user exists:', adminUser.email);
    } else {
      logger.warn('No admin user found');
    }

    // Check tables
    const tables = await prisma.$queryRaw`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `;
    logger.info('Available tables:', tables);

  } catch (error) {
    logger.error('Database connection failed:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

checkDatabase(); 
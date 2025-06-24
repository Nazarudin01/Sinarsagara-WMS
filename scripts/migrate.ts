import { PrismaClient } from '@prisma/client'
import logger from '../lib/logger'

const prisma = new PrismaClient()

async function main() {
  try {
    // Jalankan migrasi
    await prisma.$executeRaw`SELECT 1`
    logger.info('Database connection successful')

    // Tambahkan migrasi lain di sini jika diperlukan
    // Contoh: await prisma.$executeRaw`CREATE TABLE IF NOT EXISTS ...`

    logger.info('Database migration completed successfully')
  } catch (error) {
    logger.error('Error during database migration', error)
    throw error
  } finally {
    await prisma.$disconnect()
  }
}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  }) 
import { PrismaClient } from '@prisma/client'
import { hash } from 'bcryptjs'

const prisma = new PrismaClient()

async function main() {
  const email = 'admin@example.com'
  const password = 'admin123'
  const hashedPassword = await hash(password, 12)

  try {
    const user = await prisma.user.upsert({
      where: { email },
      update: {},
      create: {
        email,
        name: 'Administrator',
        password: hashedPassword,
        role: 'ADMIN',
      },
    })

    console.log('Admin user berhasil dibuat:', user)
  } catch (error) {
    console.error('Error membuat admin user:', error)
  } finally {
    await prisma.$disconnect()
  }
}

main() 
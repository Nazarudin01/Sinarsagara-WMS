import { NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import prisma from '@/lib/prisma';
import { authOptions } from '@/lib/auth';

export async function GET() {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return new NextResponse('Unauthorized', { status: 401 });
    }

    const gudang = await prisma.gudang.findMany({
      orderBy: {
        nama: 'asc',
      },
    });

    return NextResponse.json(gudang);
  } catch (error) {
    console.error('Error fetching gudang:', error);
    return new NextResponse('Internal Server Error', { status: 500 });
  }
} 
import type { Metadata, Viewport } from 'next'
import '@/globals.css'
import { Inter } from 'next/font/google'
import { Toaster } from '@/components/ui/toaster'
import { SessionProvider } from '@/components/SessionProvider'
import Sidebar from "@/components/Sidebar"

const inter = Inter({ subsets: ['latin'] })

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
}

export const metadata: Metadata = {
  title: 'WMS App',
  description: 'Warehouse Management System',
  keywords: 'manajemen gudang, sistem gudang, warehouse management',
  authors: [{ name: 'Tim Pengembang' }],
  icons: {
    icon: [
      {
        url: '/favicon.ico',
        sizes: 'any',
      },
    ],
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <SessionProvider>
          <div className="flex min-h-screen">
            <Sidebar />
            <main className="flex-1 bg-gray-50">
              {children}
            </main>
          </div>
          <Toaster />
        </SessionProvider>
      </body>
    </html>
  )
} 
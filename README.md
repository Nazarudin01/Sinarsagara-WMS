# Warehouse Management System (WMS)

Aplikasi manajemen gudang berbasis web yang dibangun dengan Next.js, TypeScript, Prisma, dan PostgreSQL.

## Fitur

- Manajemen produk (CRUD)
- Manajemen gudang (CRUD)
- Manajemen stok
- Transaksi masuk dan keluar
- Laporan
- Manajemen pengguna
- Autentikasi dan otorisasi

## Teknologi

- Next.js 14
- TypeScript
- Prisma
- PostgreSQL
- Tailwind CSS
- JWT untuk autentikasi

## Persyaratan

- Node.js 18 atau lebih baru
- PostgreSQL 12 atau lebih baru
- npm atau yarn

## Instalasi

1. Clone repository
```bash
git clone https://github.com/yourusername/wms-app.git
cd wms-app
```

2. Install dependencies
```bash
npm install
# atau
yarn install
```

3. Buat file .env dan isi dengan konfigurasi yang diperlukan
```env
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/wms_db?schema=public"
JWT_SECRET="your-secret-key"
NEXTAUTH_URL="http://localhost:3000"
NEXTAUTH_SECRET="your-nextauth-secret"
```

4. Jalankan migrasi database
```bash
npx prisma migrate dev
```

5. Jalankan aplikasi dalam mode development
```bash
npm run dev
# atau
yarn dev
```

6. Buka [http://localhost:3000](http://localhost:3000) di browser

## Struktur Proyek

```
wms-app/
├── app/                    # Direktori aplikasi Next.js
│   ├── api/               # API routes
│   ├── (auth)/           # Halaman autentikasi
│   ├── (dashboard)/      # Halaman dashboard
│   └── layout.tsx        # Layout utama
├── components/           # Komponen React
├── lib/                  # Utility functions
├── prisma/              # Konfigurasi Prisma
├── public/              # Static files
└── styles/              # Global styles
```

## API Endpoints

### Autentikasi
- POST /api/auth/login - Login
- GET /api/auth/me - Get current user

### Pengguna
- GET /api/pengguna - Get all users
- POST /api/pengguna - Create user
- PUT /api/pengguna - Update user
- DELETE /api/pengguna - Delete user

### Produk
- GET /api/produk - Get all products
- POST /api/produk - Create product
- PUT /api/produk - Update product
- DELETE /api/produk - Delete product

### Gudang
- GET /api/gudang - Get all warehouses
- POST /api/gudang - Create warehouse
- PUT /api/gudang - Update warehouse
- DELETE /api/gudang - Delete warehouse

### Stok
- GET /api/stok - Get all stock
- POST /api/stok - Create stock
- PUT /api/stok - Update stock
- DELETE /api/stok - Delete stock

### Transaksi
- GET /api/transaksi-masuk - Get all incoming transactions
- POST /api/transaksi-masuk - Create incoming transaction
- PUT /api/transaksi-masuk - Update transaction status
- GET /api/transaksi-keluar - Get all outgoing transactions
- POST /api/transaksi-keluar - Create outgoing transaction
- PUT /api/transaksi-keluar - Update transaction status

### Laporan
- GET /api/laporan - Get reports

## Lisensi

MIT

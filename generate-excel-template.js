const XLSX = require('xlsx');
const fs = require('fs');
const path = require('path');

// Data header dan contoh
const data = [
  [
    'Tanggal',
    'No Transaksi',
    'Supplier',
    'Kategori',
    'Gudang Tujuan',
    'Kode Rak',
    'SKU/Nama Barang',
    'Jumlah',
    'Penanggung Jawab',
    'Catatan'
  ],
  [
    '2024-07-01',
    '', // No Transaksi (auto)
    'PT Sumber Jaya',
    'Skincare',
    'Gudang A',
    'RK-01',
    'SKU123 - Sabun Muka',
    10,
    'Budi',
    'Barang masuk awal bulan'
  ]
];

// Buat worksheet dan workbook
const ws = XLSX.utils.aoa_to_sheet(data);
const wb = XLSX.utils.book_new();
XLSX.utils.book_append_sheet(wb, ws, 'Template');

// Path output
const outputPath = path.join(__dirname, 'wms-app', 'public', 'stok-masuk-template.xlsx');

// Simpan file Excel
XLSX.writeFile(wb, outputPath);

console.log('Template Excel berhasil dibuat di:', outputPath); 
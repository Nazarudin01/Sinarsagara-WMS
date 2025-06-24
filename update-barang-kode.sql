-- Update kode barang yang kosong dengan format B-{id}
UPDATE "Barang" 
SET "kode" = 'B-' || id 
WHERE "kode" IS NULL OR "kode" = ''; 
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useState } from "react"
import { toast } from "@/components/ui/use-toast"
import { Eye, Pencil, Trash2 } from "lucide-react"

interface DetailBarangModalProps {
  isOpen: boolean
  onClose: () => void
  barang: any
  onEdit: (data: any) => void
  onDelete: (id: string) => void
  satuanList: string[]
  jenisList: string[]
}

export default function DetailBarangModal({
  isOpen,
  onClose,
  barang,
  onEdit,
  onDelete,
  satuanList,
  jenisList
}: DetailBarangModalProps) {
  const [isEditing, setIsEditing] = useState(false)
  const [formData, setFormData] = useState({
    kategori: barang.kategori,
    satuan: barang.satuan,
    jenis: barang.jenis,
    hargaBeli: barang.hargaBeli,
    gambar: null as File | null
  })
  const [imagePreview, setImagePreview] = useState<string | null>(null)

  const handleImageChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setFormData(prev => ({ ...prev, gambar: file }))
      setImagePreview(URL.createObjectURL(file))
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    try {
      const formDataToSend = new FormData()
      formDataToSend.append('kategori', formData.kategori)
      formDataToSend.append('satuan', formData.satuan)
      formDataToSend.append('jenis', formData.jenis)
      formDataToSend.append('hargaBeli', formData.hargaBeli.toString())
      if (formData.gambar) {
        formDataToSend.append('gambar', formData.gambar)
      }

      const response = await fetch(`/api/barang/${barang.id}`, {
        method: 'PATCH',
        body: formDataToSend
      })

      if (!response.ok) {
        throw new Error('Gagal mengupdate barang')
      }

      const updatedBarang = await response.json()
      onEdit(updatedBarang)
      setIsEditing(false)
      toast({
        title: "Sukses",
        description: "Data barang berhasil diupdate",
      })
    } catch (error) {
      toast({
        title: "Error",
        description: "Gagal mengupdate data barang",
        variant: "destructive",
      })
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>Detail Produk</DialogTitle>
        </DialogHeader>

        <div className="grid grid-cols-2 gap-6">
          {/* Kolom Kiri: Gambar */}
          <div className="space-y-4">
            <div className="relative aspect-square w-full overflow-hidden rounded-lg border">
              <img
                src={imagePreview || (barang.gambar ? `/uploads/${barang.gambar}` : '/placeholder.png')}
                alt={barang.nama}
                className="object-cover w-full h-full"
                onError={(e) => {
                  const target = e.target as HTMLImageElement;
                  target.src = '/placeholder.png';
                }}
              />
              {isEditing && (
                <div className="absolute inset-0 bg-black/50 flex items-center justify-center">
                  <Input
                    type="file"
                    accept="image/*"
                    onChange={handleImageChange}
                    className="hidden"
                    id="gambar-upload"
                  />
                  <Label
                    htmlFor="gambar-upload"
                    className="cursor-pointer bg-white text-black px-4 py-2 rounded-md hover:bg-gray-100"
                  >
                    Ganti Gambar
                  </Label>
                </div>
              )}
            </div>
          </div>

          {/* Kolom Kanan: Detail */}
          <div className="space-y-4">
            {isEditing ? (
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label className="text-black">Kategori</Label>
                  <Select
                    value={formData.kategori}
                    onValueChange={(value) => setFormData(prev => ({ ...prev, kategori: value }))}
                  >
                    <SelectTrigger className="text-black">
                      <SelectValue placeholder="Pilih kategori" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Bahan Baku">Bahan Baku</SelectItem>
                      <SelectItem value="Barang Setengah Jadi">Barang Setengah Jadi</SelectItem>
                      <SelectItem value="Barang Jadi">Barang Jadi</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label className="text-black">Satuan</Label>
                  <Select
                    value={formData.satuan}
                    onValueChange={(value) => setFormData(prev => ({ ...prev, satuan: value }))}
                  >
                    <SelectTrigger className="text-black">
                      <SelectValue placeholder="Pilih satuan" />
                    </SelectTrigger>
                    <SelectContent>
                      {satuanList.map((satuan) => (
                        <SelectItem key={satuan} value={satuan}>
                          {satuan}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label className="text-black">Jenis</Label>
                  <Select
                    value={formData.jenis}
                    onValueChange={(value) => setFormData(prev => ({ ...prev, jenis: value }))}
                  >
                    <SelectTrigger className="text-black">
                      <SelectValue placeholder="Pilih jenis" />
                    </SelectTrigger>
                    <SelectContent>
                      {jenisList.map((jenis) => (
                        <SelectItem key={jenis} value={jenis}>
                          {jenis}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label className="text-black">Harga Beli</Label>
                  <Input
                    type="number"
                    value={formData.hargaBeli}
                    onChange={(e) => setFormData(prev => ({ ...prev, hargaBeli: parseFloat(e.target.value) }))}
                    className="text-black"
                  />
                </div>

                <div className="flex gap-2">
                  <Button type="submit">Simpan</Button>
                  <Button type="button" variant="outline" onClick={() => setIsEditing(false)}>
                    Batal
                  </Button>
                </div>
              </form>
            ) : (
              <>
                <div className="space-y-2">
                  <Label className="text-black">SKU</Label>
                  <p className="text-sm text-black">{barang.sku}</p>
                </div>

                <div className="space-y-2">
                  <Label className="text-black">Nama Barang</Label>
                  <p className="text-sm text-black">{barang.nama}</p>
                </div>

                <div className="space-y-2">
                  <Label className="text-black">Kategori</Label>
                  <p className="text-sm text-black">{barang.kategori}</p>
                </div>

                <div className="space-y-2">
                  <Label className="text-black">Satuan</Label>
                  <p className="text-sm text-black">{barang.satuan}</p>
                </div>

                <div className="space-y-2">
                  <Label className="text-black">Jenis</Label>
                  <p className="text-sm text-black">{barang.jenis}</p>
                </div>

                <div className="space-y-2">
                  <Label className="text-black">Harga Beli</Label>
                  <p className="text-sm text-black">Rp {barang.hargaBeli.toLocaleString()}</p>
                </div>

                <div className="flex gap-2">
                  <Button onClick={() => setIsEditing(true)}>
                    <Pencil className="w-4 h-4 mr-2" />
                    Edit
                  </Button>
                  <Button variant="destructive" onClick={() => onDelete(barang.id)}>
                    <Trash2 className="w-4 h-4 mr-2" />
                    Hapus
                  </Button>
                </div>
              </>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
} 
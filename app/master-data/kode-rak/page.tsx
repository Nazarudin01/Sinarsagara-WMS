"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Plus, Trash2 } from "lucide-react"
import { toast } from "sonner"

interface Rak {
  id: string
  kode: string
  nama: string
}

const TEMPAT_OPTIONS = [
  { value: "RK", label: "Rak (RK)" },
  { value: "ET", label: "Etalase (ET)" },
  { value: "TP", label: "Toples (TP)" },
]

export default function KodeRakPage() {
  const [rakList, setRakList] = useState<Rak[]>([])
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [formData, setFormData] = useState({
    tempat: "",
    kode: "",
    keterangan: "",
  })

  useEffect(() => {
    fetchRak()
  }, [])

  const fetchRak = async () => {
    try {
      const response = await fetch("/api/master-data/kode-rak")
      if (!response.ok) throw new Error("Failed to fetch rak data")
      const data = await response.json()
      setRakList(data.data || [])
    } catch (error) {
      console.error("Error fetching rak:", error)
      toast.error("Gagal mengambil data rak")
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const kodeRak = `${formData.tempat}-${formData.kode}`

      const response = await fetch("/api/master-data/kode-rak", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          kode: kodeRak,
          keterangan: formData.keterangan,
        }),
      })

      if (!response.ok) throw new Error("Failed to save rak")

      toast.success("Kode rak berhasil ditambahkan")
      setIsModalOpen(false)
      fetchRak()
      resetForm()
    } catch (error) {
      console.error("Error saving rak:", error)
      toast.error("Gagal menyimpan kode rak")
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm("Apakah Anda yakin ingin menghapus rak ini?")) return

    try {
      const response = await fetch(`/api/master-data/kode-rak/${id}`, {
        method: "DELETE",
      })

      if (!response.ok) throw new Error("Failed to delete rak")

      toast.success("Rak berhasil dihapus")
      fetchRak()
    } catch (error) {
      console.error("Error deleting rak:", error)
      toast.error("Gagal menghapus rak")
    }
  }

  const resetForm = () => {
    setFormData({
      tempat: "",
      kode: "",
      keterangan: "",
    })
  }

  return (
    <div className="container mx-auto py-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Master Data Kode Rak</h1>
        <Dialog open={isModalOpen} onOpenChange={setIsModalOpen}>
          <DialogTrigger asChild>
            <Button onClick={() => resetForm()}>
              <Plus className="w-4 h-4 mr-2" />
              Tambah Kode Rak
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Tambah Kode Rak Baru</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="tempat">Tempat</Label>
                <Select
                  value={formData.tempat}
                  onValueChange={(value) =>
                    setFormData((prev) => ({ ...prev, tempat: value }))
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Pilih tempat" />
                  </SelectTrigger>
                  <SelectContent>
                    {TEMPAT_OPTIONS.map((option) => (
                      <SelectItem key={option.value} value={option.value}>
                        {option.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="kode">Kode</Label>
                <Input
                  id="kode"
                  placeholder="Contoh: A-001"
                  value={formData.kode}
                  onChange={(e) =>
                    setFormData((prev) => ({ ...prev, kode: e.target.value }))
                  }
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="keterangan">Keterangan</Label>
                <Input
                  id="keterangan"
                  value={formData.keterangan}
                  onChange={(e) =>
                    setFormData((prev) => ({
                      ...prev,
                      keterangan: e.target.value,
                    }))
                  }
                  required
                />
              </div>
              <div className="flex justify-end space-x-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setIsModalOpen(false)}
                >
                  Batal
                </Button>
                <Button type="submit">Tambah</Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="bg-white rounded-lg shadow">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="text-black">Kode Rak</TableHead>
              <TableHead className="text-black">Keterangan</TableHead>
              <TableHead className="w-[150px] text-center text-black">Aksi</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rakList.map((rak) => (
              <TableRow key={rak.id}>
                <TableCell className="text-black">{rak.kode}</TableCell>
                <TableCell className="text-black">{rak.nama}</TableCell>
                <TableCell className="text-center">
                  <div className="flex justify-center space-x-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleDelete(rak.id)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  )
} 
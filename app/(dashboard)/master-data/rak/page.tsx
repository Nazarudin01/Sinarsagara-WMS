"use client";
import { Trash2 } from "lucide-react"
import { toast } from "sonner"
import { useRouter } from "next/navigation"
import { useState } from "react"

const onSubmit = async (data: FormData) => {
    try {
      setIsLoading(true)
      const kode = `${data.tempat}${data.kode}`
      console.log("Submitting data:", { kode, keterangan: data.keterangan })
      
      const response = await fetch("/api/master-data/rak", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          kode,
          keterangan: data.keterangan,
        }),
      })

      if (!response.ok) {
        const error = await response.text()
        console.error("Error response:", error)
        throw new Error(error)
      }

      const result = await response.json()
      console.log("Success response:", result)
      
      toast.success("Rak berhasil ditambahkan")
      form.reset()
      setOpen(false)
      router.refresh()
    } catch (error) {
      console.error("Error submitting:", error)
      toast.error(error instanceof Error ? error.message : "Terjadi kesalahan")
    } finally {
      setIsLoading(false)
    }
  }

const onDelete = async (id: string) => {
    try {
      const response = await fetch(`/api/master-data/rak?id=${id}`, {
        method: "DELETE",
      })

      if (!response.ok) {
        throw new Error("Failed to delete rak")
      }

      toast.success("Rak berhasil dihapus")
      router.refresh()
    } catch (error) {
      console.error("Error deleting rak:", error)
      toast.error("Gagal menghapus rak")
    }
  }

export default function RakPage() {
  const router = useRouter()
  const [isLoading, setIsLoading] = useState(false)
  const [open, setOpen] = useState(false)
  const [raks, setRaks] = useState<Rak[]>([])

  return (
    <div className="flex-1 space-y-4 p-8 pt-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold tracking-tight">Master Data Rak</h2>
        <Button onClick={() => setOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> Tambah Rak
        </Button>
      </div>
      <div className="border shadow-sm rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Kode</TableHead>
              <TableHead>Keterangan</TableHead>
              <TableHead>Tanggal Dibuat</TableHead>
              <TableHead className="text-right">Aksi</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {raks.map((rak) => (
              <TableRow key={rak.id}>
                <TableCell>{rak.kode}</TableCell>
                <TableCell>{rak.keterangan}</TableCell>
                <TableCell>
                  {new Date(rak.createdAt).toLocaleDateString("id-ID")}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => onDelete(rak.id)}
                    className="text-red-500 hover:text-red-700"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {/* ... existing modal code ... */}
    </div>
  )
} 

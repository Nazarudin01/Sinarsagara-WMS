"use client"

import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Plus, Trash2 } from "lucide-react"
import { useState, useEffect, useCallback } from "react"
import { useRouter } from "next/navigation"
import { toast } from "sonner"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { useDebounce } from "@/hooks/use-debounce"

interface Pemasok {
  id: string
  nama: string
  alamat: string
  telepon: string
  email: string
  createdAt: string
}

export default function PemasokPage() {
  const router = useRouter()
  const [isLoading, setIsLoading] = useState(false)
  const [open, setOpen] = useState(false)
  const [pemasoks, setPemasoks] = useState<Pemasok[]>([])
  const [search, setSearch] = useState("")
  const [form, setForm] = useState({ nama: "", alamat: "", telepon: "", email: "" })
  const debouncedSearch = useDebounce(search, 300)

  // Fetch pemasoks from API
  useEffect(() => {
    const fetchPemasoks = async () => {
      try {
        const url = debouncedSearch
          ? `/api/master-data/pemasok/search?q=${encodeURIComponent(debouncedSearch)}`
          : "/api/master-data/pemasok"
        const res = await fetch(url)
        if (!res.ok) throw new Error("Failed to fetch pemasoks")
        const result = await res.json()
        setPemasoks(result.data || [])
      } catch (error) {
        console.error("Error fetching pemasoks:", error)
        toast.error("Gagal memuat data pemasok")
      }
    }
    fetchPemasoks()
  }, [debouncedSearch])

  // Remove client-side filtering since we're using server-side search
  const filteredPemasoks = pemasoks

  const onDelete = async (id: string) => {
    try {
      const response = await fetch(`/api/master-data/pemasok?id=${id}`, {
        method: "DELETE",
      })
      if (!response.ok) throw new Error("Failed to delete pemasok")
      setPemasoks((prev) => prev.filter((p) => p.id !== id))
      toast.success("Pemasok berhasil dihapus")
    } catch (error) {
      toast.error("Gagal menghapus pemasok")
    }
  }

  const onChangeForm = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value })
  }

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    try {
      console.log("[PEMASOK_FORM] Submitting data:", form)
      const res = await fetch("/api/master-data/pemasok", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      })
      if (!res.ok) {
        const errorData = await res.text()
        console.error("[PEMASOK_FORM] Error response:", errorData)
        throw new Error(errorData || "Gagal menambah pemasok")
      }
      const newPemasok = await res.json()
      console.log("[PEMASOK_FORM] Success response:", newPemasok)
      setPemasoks((prev) => [newPemasok, ...prev])
      setOpen(false)
      setForm({ nama: "", alamat: "", telepon: "", email: "" })
      toast.success("Pemasok berhasil ditambahkan")
    } catch (error) {
      console.error("[PEMASOK_FORM] Error:", error)
      toast.error(error instanceof Error ? error.message : "Gagal menambah pemasok")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="flex-1 space-y-4 p-8 pt-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold tracking-tight">Master Data Pemasok</h2>
        <Button onClick={() => setOpen(true)}>
          <Plus className="mr-2 h-4 w-4" /> Tambah Pemasok
        </Button>
      </div>
      <Input
        placeholder="Cari pemasok..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="mb-4 w-64 rounded-full"
      />
      <div className="border shadow-sm rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Nama</TableHead>
              <TableHead>Alamat</TableHead>
              <TableHead>Telepon</TableHead>
              <TableHead>Email</TableHead>
              <TableHead className="text-right">Aksi</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredPemasoks.map((pemasok) => (
              <TableRow key={pemasok.id}>
                <TableCell>{pemasok.nama}</TableCell>
                <TableCell>{pemasok.alamat}</TableCell>
                <TableCell>{pemasok.telepon}</TableCell>
                <TableCell>{pemasok.email}</TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => onDelete(pemasok.id)}
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
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Tambah Pemasok Baru</DialogTitle>
          </DialogHeader>
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="space-y-2">
              <Label htmlFor="nama">Nama Pemasok</Label>
              <Input id="nama" name="nama" value={form.nama} onChange={onChangeForm} required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="alamat">Alamat</Label>
              <Textarea id="alamat" name="alamat" value={form.alamat} onChange={onChangeForm} required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="telepon">Telepon</Label>
              <Input id="telepon" name="telepon" value={form.telepon} onChange={onChangeForm} required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" name="email" type="email" value={form.email} onChange={onChangeForm} required />
            </div>
            <Button type="submit" className="w-full" disabled={isLoading}>
              {isLoading ? "Menyimpan..." : "Simpan"}
            </Button>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
} 
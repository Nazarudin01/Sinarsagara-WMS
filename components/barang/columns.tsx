"use client"

import { ColumnDef } from "@tanstack/react-table"
import { MoreHorizontal, ArrowUpDown } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

export type Barang = {
  id: string
  sku: string
  nama: string
  kategori: string
  satuan: string
  jenis: string
  hargaBeli: number
  gambar?: string
}

interface ColumnsProps {
    onEdit: (barang: Barang) => void;
    onDelete: (id: string) => void;
}

export function columns({ onEdit, onDelete }: ColumnsProps): ColumnDef<Barang>[] {
  return [
    {
      accessorKey: "sku",
      header: ({ column }) => {
        return (
          <Button
            variant="ghost"
            onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
          >
            SKU
            <ArrowUpDown className="ml-2 h-4 w-4" />
          </Button>
        )
      },
    },
    {
      accessorKey: "nama",
      header: "Nama Barang",
    },
    {
      accessorKey: "kategori",
      header: "Kategori",
    },
    {
      accessorKey: "satuan",
      header: "Satuan",
    },
    {
      accessorKey: "hargaBeli",
      header: "Harga Beli",
      cell: ({ row }) => {
          const amount = parseFloat(row.getValue("hargaBeli"))
          const formatted = new Intl.NumberFormat("id-ID", {
            style: "currency",
            currency: "IDR",
          }).format(amount)
     
          return <div className="font-medium">{formatted}</div>
        },
    },
    {
      id: "actions",
      cell: ({ row }) => {
        const barang = row.original
  
        return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="h-8 w-8 p-0">
                <span className="sr-only">Buka menu</span>
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Aksi</DropdownMenuLabel>
              <DropdownMenuItem onClick={() => onEdit(barang)}>
                Edit
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => onDelete(barang.id)} className="text-red-500">
                Hapus
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )
      },
    },
  ]
} 
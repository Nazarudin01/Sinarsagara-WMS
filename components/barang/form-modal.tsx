"use client";

import { useEffect, useState, useRef } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { useToast } from "@/components/ui/use-toast";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Paperclip } from "lucide-react";
import { ComboboxDinamis } from "./combobox-dinamis";

const formSchema = z.object({
  sku: z.string().min(1, "SKU harus diisi"),
  nama: z.string().min(1, "Nama barang harus diisi"),
  kategori: z.string().min(1, "Kategori harus dipilih"),
  satuan: z.string().min(1, "Satuan harus dipilih"),
  jenis: z.string().min(1, "Jenis harus dipilih"),
  hargaBeli: z.coerce.number().min(0, "Harga beli tidak boleh negatif"),
  gambar: z.any().optional(),
});

interface BarangFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  barangData?: any | null;
  satuanList: { id: string; nama: string }[];
  jenisList: { id: string; nama: string }[];
  onDataMasterChange: () => void;
}

export function BarangFormModal({
  isOpen,
  onClose,
  onSuccess,
  barangData,
  satuanList,
  jenisList,
  onDataMasterChange
}: BarangFormModalProps) {
  const { toast } = useToast();
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      sku: "",
      nama: "",
      kategori: "",
      satuan: "",
      jenis: "",
      hargaBeli: 0,
    },
  });

  useEffect(() => {
    if (barangData) {
      form.reset(barangData);
      if (barangData.gambar) {
        setImagePreview(`/uploads/${barangData.gambar}`);
        setFileName(barangData.gambar);
      } else {
        setImagePreview(null);
        setFileName("");
      }
    } else {
      form.reset({
        sku: "",
        nama: "",
        kategori: "",
        satuan: "",
        jenis: "",
        hargaBeli: 0,
        gambar: undefined,
      });
      setImagePreview(null);
      setFileName("");
    }
  }, [barangData, form]);

  const onSubmit = async (values: z.infer<typeof formSchema>) => {
    try {
      const formData = new FormData();
      Object.entries(values).forEach(([key, value]) => {
        if (key === 'gambar' && value && value.length > 0) {
          formData.append('gambar', value[0]);
        } else if (key !== 'gambar') {
          formData.append(key, String(value));
        }
      });

      const method = barangData ? 'PUT' : 'POST';
      const url = barangData ? `/api/master-data/barang/${barangData.id}` : '/api/master-data/barang';

      const response = await fetch(url, { method, body: formData });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Gagal menyimpan data barang');
      }

      toast({
        title: "Berhasil!",
        description: `Data barang berhasil ${barangData ? 'diperbarui' : 'disimpan'}.`,
      });
      onSuccess();
    } catch (error) {
      toast({
        title: "Error",
        description: (error as Error).message,
        variant: "destructive",
      });
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="z-[9999]">
        <DialogHeader>
          <DialogTitle>{barangData ? "Edit Barang" : "Tambah Barang"}</DialogTitle>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4 max-h-[80vh] overflow-y-auto pr-4">
            <FormField
              control={form.control}
              name="gambar"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Gambar</FormLabel>
                  <FormControl>
                    <div>
                      <Input 
                        type="file" 
                        accept="image/*"
                        className="hidden"
                        ref={fileInputRef}
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          field.onChange(e.target.files);
                          if (file) {
                            setImagePreview(URL.createObjectURL(file));
                            setFileName(file.name);
                          } else {
                            setImagePreview(null);
                            setFileName('');
                          }
                        }}
                      />
                      <div className="flex items-center gap-2">
                        <Button type="button" variant="outline" onClick={() => fileInputRef.current?.click()}>
                          <Paperclip className="mr-2 h-4 w-4" />
                          Pilih File
                        </Button>
                        {fileName && <p className="text-sm text-muted-foreground truncate">{fileName}</p>}
                      </div>
                    </div>
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            {imagePreview && (
              <div className="mt-2">
                <img src={imagePreview} alt="Preview" className="w-32 h-32 object-cover rounded-md" />
              </div>
            )}
            <FormField
              control={form.control}
              name="sku"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>SKU</FormLabel>
                  <FormControl>
                    <Input placeholder="SKU Barang" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="nama"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Nama Barang</FormLabel>
                  <FormControl>
                    <Input placeholder="Nama Barang" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
             <FormField
              control={form.control}
              name="kategori"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Kategori</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Pilih Kategori" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="Bahan Baku">Bahan Baku</SelectItem>
                      <SelectItem value="Barang Setengah Jadi">Barang Setengah Jadi</SelectItem>
                      <SelectItem value="Barang Jadi">Barang Jadi</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="satuan"
              render={({ field }) => (
                <FormItem className="flex flex-col">
                  <FormLabel>Satuan</FormLabel>
                   <ComboboxDinamis
                      options={satuanList}
                      value={field.value}
                      onChange={(value) => form.setValue('satuan', value, { shouldValidate: true })}
                      onDataMasterChange={onDataMasterChange}
                      placeholder="Pilih Satuan..."
                      searchPlaceholder="Cari Satuan..."
                      emptyMessage="Satuan tidak ditemukan."
                      apiEndpoint="/api/master-data/satuan"
                      dialogTitle="Tambah Satuan Baru"
                      dialogLabel="Satuan"
                   />
                  <FormMessage />
                </FormItem>
              )}
            />
             <FormField
              control={form.control}
              name="jenis"
              render={({ field }) => (
                <FormItem className="flex flex-col">
                  <FormLabel>Jenis</FormLabel>
                  <ComboboxDinamis
                      options={jenisList}
                      value={field.value}
                      onChange={(value) => form.setValue('jenis', value, { shouldValidate: true })}
                      onDataMasterChange={onDataMasterChange}
                      placeholder="Pilih Jenis..."
                      searchPlaceholder="Cari Jenis..."
                      emptyMessage="Jenis tidak ditemukan."
                      apiEndpoint="/api/master-data/jenis"
                      dialogTitle="Tambah Jenis Baru"
                      dialogLabel="Jenis"
                   />
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="hargaBeli"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Harga Beli</FormLabel>
                  <FormControl>
                    <Input type="number" placeholder="0" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <DialogFooter className="sticky bottom-0 bg-background pt-4">
                <Button type="button" variant="outline" onClick={onClose}>Batal</Button>
                <Button type="submit">Simpan</Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
} 
"use client";

import { useState, useEffect } from "react";
import { useForm, useFieldArray } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import * as z from "zod";
import { format } from "date-fns";
import { id } from "date-fns/locale";
import { CalendarIcon, Trash2 } from "lucide-react";
import { useToast } from "@/components/ui/use-toast";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Calendar } from "@/components/ui/calendar";
import { cn } from "@/lib/utils";
import { ComboboxSearch } from "@/components/stok-masuk/combobox-search"; // Re-using this component

// Zod Schema
const itemSchema = z.object({
  barangId: z.string().min(1, "Barang harus dipilih"),
  jumlah: z.number().min(1, "Jumlah minimal 1"),
  satuan: z.string().optional(),
});

const formSchema = z.object({
  nomor: z.string(),
  tanggal: z.date(),
  pelangganId: z.string().min(1, "Pelanggan harus dipilih"),
  gudangId: z.string().min(1, "Gudang harus dipilih"),
  items: z.array(itemSchema).min(1, "Minimal harus ada satu item barang"),
});

// Mock data (replace with actual API calls)
const fetchPelanggan = async () => {
  const res = await fetch("/api/master-data/pelanggan");
  const data = await res.json();
  return data.data || [];
};
const fetchGudang = async () => {
  const res = await fetch("/api/master/gudang");
  if (!res.ok) return [];
  const data = await res.json();
  return data.data || [];
};
const fetchBarangByGudang = async (gudangId: string) => {
  if (!gudangId) return [];
  const res = await fetch(`/api/master-data/gudang/${gudangId}/barang`);
  const data = await res.json();
  return data || [];
};

export function StokKeluarFormModal({ isOpen, onClose, onSuccess }: {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState(false);

  // Data states
  const [pelangganList, setPelangganList] = useState<any[]>([]);
  const [gudangList, setGudangList] = useState<any[]>([]);
  const [barangList, setBarangList] = useState<any[]>([]);
  const [filteredBarang, setFilteredBarang] = useState<any[]>([]);

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      tanggal: new Date(),
      items: [{ barangId: "", jumlah: 1, satuan: "" }],
    },
  });

  const { fields, append, remove } = useFieldArray({
    control: form.control,
    name: "items",
  });

  const selectedGudangId = form.watch("gudangId");

  useEffect(() => {
    if (!isOpen) return;
    
    const loadInitialData = async () => {
      try {
        const [nomorRes, pelangganData, gudangData] = await Promise.all([
          fetch("/api/stok-keluar/generate-nomor"),
          fetchPelanggan(),
          fetchGudang(),
        ]);
        
        const nomorData = await nomorRes.json();
        form.setValue("nomor", nomorData.nomor);
        setPelangganList(pelangganData);
        setGudangList(gudangData);

      } catch (error) {
        toast({ title: "Error", description: "Gagal memuat data awal", variant: "destructive" });
      }
    };
    loadInitialData();
  }, [isOpen, form, toast]);

  useEffect(() => {
    if (selectedGudangId) {
      const loadBarang = async () => {
        const data = await fetchBarangByGudang(selectedGudangId);
        setBarangList(data);
        console.log('Barang dari API:', data);
      };
      loadBarang();
    } else {
      setBarangList([]);
    }
  }, [selectedGudangId]);
  
  const handleBarangChange = (barangId: string, index: number) => {
    const selected = barangList.find(b => b.id === barangId);
    if(selected) {
        form.setValue(`items.${index}.satuan`, selected.satuan);
    }
  };
  
  const onSubmit = async (data: z.infer<typeof formSchema>) => {
    setIsLoading(true);
    try {
      const response = await fetch('/api/stok-keluar', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(errorText || 'Gagal menyimpan data');
      }

      toast({
        title: "Sukses",
        description: "Data stok keluar berhasil disimpan.",
        variant: "success",
      });
      onSuccess(); // This will trigger data refresh on the parent page
      onClose();
      form.reset();

    } catch (error: any) {
      toast({
        title: "Error",
        description: error.message || "Terjadi kesalahan saat menyimpan data.",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => {
      if (!open) {
        form.reset({
          tanggal: new Date(),
          items: [{ barangId: "", jumlah: 1, satuan: "" }],
        });
        onClose();
      }
    }}>
      <DialogContent className="sm:max-w-4xl rounded-2xl">
        <DialogHeader><DialogTitle>Buat Stok Keluar</DialogTitle></DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <FormField name="nomor" control={form.control} render={({ field }) => (
                    <FormItem><FormLabel>Nomor Transaksi</FormLabel><FormControl><Input {...field} disabled /></FormControl></FormItem>
                )} />
                <FormField name="tanggal" control={form.control} render={({ field }) => (
                    <FormItem>
                      <FormLabel>Tanggal</FormLabel>
                      <Popover>
                        <PopoverTrigger asChild>
                          <FormControl>
                            <Button
                              variant={"outline"}
                              className={cn("w-full justify-start text-left font-normal", !field.value && "text-muted-foreground")}
                            >
                              <CalendarIcon className="mr-2 h-4 w-4" />
                              {field.value ? format(field.value, "PPP", { locale: id }) : <span>Pilih tanggal</span>}
                            </Button>
                          </FormControl>
                        </PopoverTrigger>
                        <PopoverContent className="w-auto p-0"><Calendar mode="single" selected={field.value} onSelect={field.onChange} /></PopoverContent>
                      </Popover>
                      <FormMessage />
                    </FormItem>
                )} />
                 <FormField name="pelangganId" control={form.control} render={({ field }) => (
                    <FormItem><FormLabel>Pelanggan</FormLabel><FormControl>
                        <ComboboxSearch options={pelangganList} value={field.value} onChange={field.onChange} placeholder="Pilih Pelanggan" searchPlaceholder="Cari Pelanggan..." emptyMessage="Pelanggan tidak ditemukan." />
                    </FormControl><FormMessage /></FormItem>
                )} />
                 <FormField name="gudangId" control={form.control} render={({ field }) => (
                    <FormItem><FormLabel>Gudang</FormLabel><FormControl>
                        <ComboboxSearch options={gudangList} value={field.value} onChange={field.onChange} placeholder="Pilih Gudang" searchPlaceholder="Cari Gudang..." emptyMessage="Gudang tidak ditemukan." />
                    </FormControl><FormMessage /></FormItem>
                )} />
            </div>

            <div className="pt-4 border-t">
              <h3 className="text-lg font-semibold mb-2">Item Barang</h3>
              <div className="flex flex-col gap-4">
                <div className="grid grid-cols-12 gap-x-4 p-2 font-semibold">
                  <div className="col-span-5">Barang</div>
                  <div className="col-span-2">Stok Tersedia</div>
                  <div className="col-span-2">Jumlah</div>
                  <div className="col-span-2">Satuan</div>
                  <div className="col-span-1"></div>
                </div>
                {fields.map((item, index) => {
                  const selected = barangList.find(b => (b.id || b.barangId) === form.watch(`items.${index}.barangId`));
                  return (
                    <div key={item.id} className="grid grid-cols-12 gap-x-4 p-2 border rounded-md items-end">
                      <div className="col-span-5">
                        <FormField name={`items.${index}.barangId`} control={form.control} render={({ field }) => (
                          <FormItem><FormLabel className="md:hidden">Barang</FormLabel><FormControl>
                              <ComboboxSearch 
                                 options={barangList.map(b => ({ id: b.id || b.barangId, nama: b.nama || b.nama_barang }))} 
                                 value={field.value} 
                                 onChange={(val) => { field.onChange(val); handleBarangChange(val, index); }} 
                                 placeholder="Pilih Barang" 
                                 searchPlaceholder="Cari Barang..." 
                                 emptyMessage="Barang tidak ditemukan." 
                                 disabled={!selectedGudangId} 
                              />
                          </FormControl><FormMessage /></FormItem>
                        )} />
                      </div>
                      <div className="col-span-2">
                        <Input value={selected?.stok ?? ''} disabled />
                      </div>
                      <div className="col-span-2">
                          <FormField name={`items.${index}.jumlah`} control={form.control} render={({ field }) => (
                              <FormItem><FormLabel className="md:hidden">Jumlah</FormLabel><FormControl><Input type="number" {...field} onChange={e => field.onChange(parseInt(e.target.value, 10))} /></FormControl><FormMessage /></FormItem>
                          )} />
                      </div>
                      <div className="col-span-2">
                          <FormField name={`items.${index}.satuan`} control={form.control} render={({ field }) => (
                              <FormItem><FormLabel className="md:hidden">Satuan</FormLabel><FormControl><Input {...field} disabled /></FormControl></FormItem>
                          )} />
                      </div>
                      <div className="col-span-1">
                        <Button type="button" variant="ghost" size="icon" onClick={() => remove(index)} disabled={fields.length <= 1}><Trash2 className="h-4 w-4 text-red-500" /></Button>
                      </div>
                    </div>
                  );
                })}
              </div>
              <Button type="button" variant="outline" onClick={() => append({ barangId: "", jumlah: 1, satuan: "" })} className="mt-4">Tambah Item</Button>
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>Batal</Button>
              <Button type="submit" disabled={isLoading}>{isLoading ? "Menyimpan..." : "Simpan"}</Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
} 
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
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
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
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Calendar } from "@/components/ui/calendar";
import { cn } from "@/lib/utils";
import { ComboboxSearch } from "./combobox-search";

const itemSchema = z.object({
  rakId: z.string().min(1, "Rak harus dipilih"),
  productId: z.string().min(1, "Barang harus dipilih"),
  quantity: z.number().min(1, "Jumlah minimal 1"),
  satuan: z.string().optional(),
});

const formSchema = z.object({
  nomor: z.string().min(1, "Nomor harus diisi"),
  tanggal: z.date({ required_error: "Tanggal harus diisi" }),
  pemasokId: z.string().min(1, "Pemasok harus dipilih"),
  kategori: z.string().min(1, "Kategori harus dipilih"),
  gudangId: z.string().min(1, "Gudang harus dipilih"),
  items: z.array(itemSchema).min(1, "Minimal harus ada satu item barang"),
});

interface StokMasukFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (data: any) => void;
}

export function StokMasukFormModal({
  isOpen,
  onClose,
  onSuccess,
}: StokMasukFormModalProps) {
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState(false);
  
  // States untuk data master
  const [pemasok, setPemasok] = useState<any[]>([]);
  const [gudang, setGudang] = useState<any[]>([]);
  const [rak, setRak] = useState<any[]>([]);
  const [allBarang, setAllBarang] = useState<any[]>([]);
  
  // State untuk data yang difilter
  const [filteredBarang, setFilteredBarang] = useState<any[]>([]);
  
  // State untuk nilai terpilih
  const [kategoriTerpilih, setKategoriTerpilih] = useState<string>("");

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      tanggal: new Date(),
      items: [],
      pemasokId: "",
      kategori: "",
      gudangId: "",
    },
  });

  const { fields, append, remove, replace } = useFieldArray({
    control: form.control,
    name: "items",
  });

  // 1. Fetch semua data master saat modal dibuka
  useEffect(() => {
    const fetchAllMasterData = async () => {
      if (!isOpen) return;
      try {
        const noCache = `?_=${new Date().getTime()}`;
        const [pemasokRes, gudangRes, rakRes, barangRes, nomorRes] = await Promise.all([
          fetch(`/api/master-data/pemasok${noCache}`),
          fetch(`/api/master/gudang${noCache}`),
          fetch(`/api/master-data/kode-rak${noCache}`),
          fetch(`/api/master-data/barang${noCache}`),
          fetch(`/api/stok-masuk/generate-nomor${noCache}`),
        ]);

        // Helper untuk parse JSON
        const parseJson = (res: Response) => {
            if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
            return res.json();
        };

        const pemasokData = await parseJson(pemasokRes);
        const gudangData = await parseJson(gudangRes);
        const rakData = await parseJson(rakRes);
        const barangData = await parseJson(barangRes);
        const nomorData = await parseJson(nomorRes);
        
        setPemasok(pemasokData.data || []);
        setGudang(gudangData.data || []);
        setRak(rakData.data || []);
        setAllBarang(barangData.data || []);
        form.setValue("nomor", nomorData.nomor);
        
      } catch (error) {
        toast({ title: "Error", description: `Gagal memuat data master: ${(error as Error).message}`, variant: "destructive" });
      }
    };
    
    if (isOpen) {
      fetchAllMasterData();
      replace([{ rakId: "", productId: "", quantity: 1, satuan: "" }]);
    } else {
        form.reset();
        setKategoriTerpilih("");
        setFilteredBarang([]);
    }
  }, [isOpen, form, replace, toast]);

  // 2. Filter barang ketika kategori berubah
  useEffect(() => {
    if (kategoriTerpilih && allBarang.length > 0) {
      const normalize = (str: string) => str.replace(/ /g, "_").toUpperCase();
      const normalizedKategori = normalize(kategoriTerpilih);

      const filtered = allBarang.filter(
        (b) => normalize(b.kategori) === normalizedKategori
      );
      setFilteredBarang(filtered);
    } else {
      setFilteredBarang([]);
    }
  }, [kategoriTerpilih, allBarang]);

  const handleKategoriChange = (value: string) => {
    setKategoriTerpilih(value);
    form.setValue("kategori", value);
    replace([{ rakId: "", productId: "", quantity: 1, satuan: "" }]);
  };

  const handleBarangChange = (productId: string, index: number) => {
    const selectedBarang = allBarang.find(b => b.id === productId);
    if (selectedBarang) {
      form.setValue(`items.${index}.satuan`, selectedBarang.satuan || '');
    }
  };

  const onSubmit = async (data: z.infer<typeof formSchema>) => {
    setIsLoading(true);
    try {
      const itemsWithDetails = data.items.map((item) => {
        const selectedBarang = allBarang.find((b) => b.id === item.productId);
        if (!selectedBarang)
          throw new Error(`Data barang untuk ID ${item.productId} tidak ditemukan`);
      return {
          sku: selectedBarang.sku,
          nama_barang: selectedBarang.nama,
          qty: item.quantity,
          harga: selectedBarang.hargaBeli || 0,
          kodeRakId: item.rakId,
      };
    });

      const formValues = form.getValues();
    const payload = {
        nomor: data.nomor,
        tanggal: format(data.tanggal, "yyyy-MM-dd"),
        pemasok: data.pemasokId,
        gudang: data.gudangId,
        items: itemsWithDetails,
    };

      const response = await fetch("/api/stok-masuk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || "Gagal menyimpan data stok masuk");
      }

      const result = await response.json();
      toast({
        title: "Berhasil",
        description: "Data stok masuk berhasil disimpan",
      });
      onSuccess?.(result);
      onClose();
    } catch (error) {
      toast({
        title: "Error",
        description: (error as Error).message,
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-4xl rounded-2xl">
        <DialogHeader>
          <DialogTitle>Form Stok Masuk</DialogTitle>
        </DialogHeader>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="nomor"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Nomor Transaksi</FormLabel>
                    <FormControl>
                      <Input {...field} disabled />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="tanggal"
                render={({ field }) => (
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
                      <PopoverContent className="w-auto p-0"><Calendar mode="single" selected={field.value} onSelect={field.onChange} initialFocus /></PopoverContent>
                    </Popover>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="pemasokId"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Pemasok</FormLabel>
                    <FormControl>
                      <ComboboxSearch
                        options={pemasok}
                        value={field.value}
                        onChange={field.onChange}
                        placeholder="Pilih Pemasok"
                        searchPlaceholder="Cari Pemasok..."
                        emptyMessage="Pemasok tidak ditemukan."
                      />
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
                    <FormControl>
                      <Select onValueChange={handleKategoriChange} value={kategoriTerpilih}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Pilih Kategori" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="Bahan Baku">Bahan Baku</SelectItem>
                          <SelectItem value="Barang Setengah Jadi">
                            Barang Setengah Jadi
                          </SelectItem>
                          <SelectItem value="Barang Jadi">Barang Jadi</SelectItem>
                        </SelectContent>
                      </Select>
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="gudangId"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Gudang</FormLabel>
                    <Select
                      onValueChange={field.onChange}
                      value={field.value}
                    >
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="Pilih Gudang" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {gudang.map((g) => (
                          <SelectItem key={g.id} value={g.id}>
                            {g.nama}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <div className="pt-4">
              <h3 className="text-lg font-semibold mb-2">Item Barang</h3>
              <div className="flex flex-col gap-4">
                {fields.map((item, index) => (
                  <div
                    key={item.id}
                    className="grid grid-cols-12 gap-x-4 gap-y-2 p-4 border rounded-md relative"
                  >
                    <div className="col-span-12 md:col-span-3">
                      <FormField
                        control={form.control}
                        name={`items.${index}.rakId`}
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Rak</FormLabel>
                            <FormControl>
                              <ComboboxSearch
                                options={rak.map(r => ({id: r.id, nama: r.kode}))}
                                value={field.value}
                                onChange={field.onChange}
                                placeholder="Pilih Rak"
                                searchPlaceholder="Cari Rak..."
                                emptyMessage="Rak tidak ditemukan."
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>
                    <div className="col-span-12 md:col-span-4">
                       <FormField
                        control={form.control}
                        name={`items.${index}.productId`}
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Barang</FormLabel>
                             <FormControl>
                              <ComboboxSearch
                                options={filteredBarang.map(b => ({id: b.id, nama: b.nama}))}
                                value={field.value}
                                onChange={(value) => {
                                  field.onChange(value);
                                  handleBarangChange(value, index);
                                }}
                                placeholder="Pilih Barang"
                                searchPlaceholder="Cari Barang..."
                                emptyMessage="Barang tidak ditemukan."
                                disabled={!kategoriTerpilih}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>
                    <div className="col-span-12 md:col-span-2">
                       <FormField
                        control={form.control}
                        name={`items.${index}.quantity`}
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Jumlah</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                {...field}
                                onChange={(e) => field.onChange(parseInt(e.target.value, 10) || 1)}
                                value={field.value || 1}
                              />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>
                     <div className="col-span-12 md:col-span-2">
                       <FormField
                        control={form.control}
                        name={`items.${index}.satuan`}
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Satuan</FormLabel>
                            <FormControl>
                              <Input {...field} disabled />
                            </FormControl>
                          </FormItem>
                        )}
                      />
                    </div>
                    <div className="col-span-12 md:col-span-1 flex items-end justify-end">
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        onClick={() => remove(index)}
                        disabled={fields.length <= 1}
                      >
                        <Trash2 className="h-4 w-4 text-red-500" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
              <Button
                type="button"
                variant="outline"
                onClick={() => append({ rakId: "", productId: "", quantity: 1, satuan: "" })}
                className="mt-4"
              >
                Tambah Item
              </Button>
            </div>

            <div className="flex justify-end gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={onClose}
                disabled={isLoading}
              >
                Batal
              </Button>
              <Button type="submit" disabled={isLoading}>
                {isLoading ? "Menyimpan..." : "Simpan"}
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
} 

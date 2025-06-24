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

const itemSchema = z.object({
  rakId: z.string().min(1, "Rak harus dipilih"),
  productId: z.string().min(1, "Barang harus dipilih"),
  quantity: z.number().min(1, "Jumlah minimal 1"),
  price: z.number().min(0, "Harga tidak boleh negatif"),
});

const formSchema = z.object({
  nomor: z.string().min(1, "Nomor harus diisi"),
  tanggal: z.date({ required_error: "Tanggal harus diisi" }),
  pemasokId: z.string().min(1, "Pemasok harus dipilih"),
  kategori: z.string().min(1, "Kategori harus dipilih"),
  gudangId: z.string().min(1, "Gudang harus dipilih"),
  items: z.array(itemSchema).min(1, "Minimal harus ada satu item barang"),
});

export function StokMasukForm({ onSuccess }: { onSuccess?: (data: any) => void }) {
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState(false);
  const [pemasok, setPemasok] = useState<any[]>([]);
  const [gudang, setGudang] = useState<any[]>([]);
  const [rak, setRak] = useState<any[]>([]);
  const [barang, setBarang] = useState<any[]>([]);
  const [kategoriTerpilih, setKategoriTerpilih] = useState<string>("");

  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      tanggal: new Date(),
      items: [{ rakId: "", productId: "", quantity: 1, price: 0 }],
    },
  });
  
  const { fields, append, remove } = useFieldArray({
    control: form.control,
    name: "items",
  });

  // Ambil nomor transaksi saat form dibuka
  useEffect(() => {
    const ambilNomor = async () => {
      try {
        const response = await fetch("/api/stok-masuk/generate-nomor");
        if (!response.ok) throw new Error("Gagal mengambil nomor transaksi");
        const data = await response.json();
        form.setValue("nomor", data.nomor);
      } catch (error) {
        toast({
          title: "Error",
          description: "Gagal mengambil nomor transaksi",
          variant: "destructive",
        });
      }
    };
    ambilNomor();
  }, [form, toast]);

  // Ambil data pemasok, gudang, rak, barang
  useEffect(() => {
    const fetchData = async (type: string, setter: Function, params = "") => {
      try {
        const response = await fetch(`/api/stok-masuk/related?type=${type}${params}`);
        if (!response.ok) throw new Error(`Gagal mengambil data ${type}`);
        const data = await response.json();
        setter(data || []);
      } catch (error) {
        toast({
          title: "Error",
          description: (error as Error).message,
          variant: "destructive",
        });
      }
    };
    fetchData("pemasok", setPemasok);
  }, [toast]);

  useEffect(() => {
    const fetchData = async (type: string, setter: Function, params = "") => {
      try {
        const response = await fetch(`/api/stok-masuk/related?type=${type}${params}`);
        if (!response.ok) throw new Error(`Gagal mengambil data ${type}`);
        const data = await response.json();
        setter(data || []);
      } catch (error) {
        toast({
          title: "Error",
          description: (error as Error).message,
          variant: "destructive",
        });
      }
    };

    if (kategoriTerpilih) {
      fetchData("gudang", setGudang, `&category=${kategoriTerpilih}`);
      fetchData("rak", setRak, `&category=${kategoriTerpilih}`);
      fetchData("barang", setBarang, `&category=${kategoriTerpilih}`);
    } else {
      setGudang([]);
      setRak([]);
      setBarang([]);
    }
  }, [kategoriTerpilih, toast]);
  
  const handleKategoriChange = (value: string) => {
    setKategoriTerpilih(value);
    form.resetField("gudangId");
    form.setValue("items", [{ rakId: "", productId: "", quantity: 1, price: 0 }]);
  };
  
  const onSubmit = async (data: z.infer<typeof formSchema>) => {
    setIsLoading(true);
    try {
      const itemsWithDetails = data.items.map(item => {
        const selectedBarang = barang.find(b => b.id === item.productId);
        return {
          sku: selectedBarang?.sku,
          nama_barang: selectedBarang?.nama,
          qty: item.quantity,
          harga: item.price,
          kodeRak: item.rakId,
        };
      });

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
      form.reset();
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
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <FormField
            control={form.control}
            name="nomor"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Nomor Transaksi</FormLabel>
                <FormControl><Input {...field} disabled /></FormControl>
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
                <Select onValueChange={field.onChange} defaultValue={field.value}>
                  <FormControl><SelectTrigger><SelectValue placeholder="Pilih pemasok" /></SelectTrigger></FormControl>
                  <SelectContent>{pemasok.map((p) => (<SelectItem key={p.id} value={p.id}>{p.nama}</SelectItem>))}</SelectContent>
                </Select>
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
                <Select
                  onValueChange={(value) => {
                    field.onChange(value);
                    handleKategoriChange(value);
                  }}
                  defaultValue={field.value}
                >
                  <FormControl><SelectTrigger><SelectValue placeholder="Pilih kategori" /></SelectTrigger></FormControl>
                  <SelectContent>
                    <SelectItem value="BAHAN_BAKU">Bahan Baku</SelectItem>
                    <SelectItem value="BARANG_SETENGAH_JADI">Barang Setengah Jadi</SelectItem>
                    <SelectItem value="BARANG_JADI">Barang Jadi</SelectItem>
                  </SelectContent>
                </Select>
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
                <Select onValueChange={field.onChange} defaultValue={field.value} disabled={!kategoriTerpilih}>
                  <FormControl><SelectTrigger><SelectValue placeholder="Pilih gudang" /></SelectTrigger></FormControl>
                  <SelectContent>{gudang.map((g) => (<SelectItem key={g.id} value={g.id}>{g.nama}</SelectItem>))}</SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <div className="space-y-4 pt-4 border-t">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-medium">Item Barang</h3>
            <Button type="button" variant="outline" onClick={() => append({ rakId: "", productId: "", quantity: 1, price: 0 })}>
              Tambah Item
            </Button>
          </div>
          <div className="space-y-4">
            {fields.map((field, index) => (
              <div key={field.id} className="grid grid-cols-1 md:grid-cols-5 gap-4 items-end p-4 border rounded-md">
                <FormField
                  control={form.control}
                  name={`items.${index}.rakId`}
                  render={({ field: selectField }) => (
                    <FormItem>
                      <FormLabel>Rak</FormLabel>
                      <Select onValueChange={selectField.onChange} defaultValue={selectField.value} disabled={!kategoriTerpilih}>
                        <FormControl><SelectTrigger><SelectValue placeholder="Pilih rak" /></SelectTrigger></FormControl>
                        <SelectContent>{rak.map((r) => (<SelectItem key={r.id} value={r.id}>{r.nama}</SelectItem>))}</SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name={`items.${index}.productId`}
                  render={({ field: selectField }) => (
                    <FormItem>
                      <FormLabel>Barang</FormLabel>
                      <Select onValueChange={selectField.onChange} defaultValue={selectField.value} disabled={!kategoriTerpilih}>
                        <FormControl><SelectTrigger><SelectValue placeholder="Pilih barang" /></SelectTrigger></FormControl>
                        <SelectContent>{barang.map((b) => (<SelectItem key={b.id} value={b.id}>{b.nama}</SelectItem>))}</SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name={`items.${index}.quantity`}
                  render={({ field: inputField }) => (
                    <FormItem>
                      <FormLabel>Jumlah</FormLabel>
                      <FormControl><Input type="number" min="1" {...inputField} onChange={(e) => inputField.onChange(Number(e.target.value))} /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name={`items.${index}.price`}
                  render={({ field: inputField }) => (
                    <FormItem>
                      <FormLabel>Harga</FormLabel>
                      <FormControl><Input type="number" min="0" {...inputField} onChange={(e) => inputField.onChange(Number(e.target.value))} /></FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button type="button" variant="destructive" size="icon" onClick={() => remove(index)}>
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            ))}
          </div>
        </div>

        <Button type="submit" className="w-full" disabled={isLoading}>
          {isLoading ? "Menyimpan..." : "Simpan"}
        </Button>
      </form>
    </Form>
  );
} 
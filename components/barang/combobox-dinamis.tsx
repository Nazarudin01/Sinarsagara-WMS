"use client";

import { useState } from "react";
import { Check, ChevronsUpDown, Plus } from "lucide-react";
import { useToast } from "@/components/ui/use-toast";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator
} from "@/components/ui/command";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { AddNewDialog } from "./add-new-dialog";

interface ComboboxDinamisProps {
  options: { id: string; nama: string }[];
  value: string;
  onChange: (value: string) => void;
  onDataMasterChange: () => void;
  placeholder: string;
  searchPlaceholder: string;
  emptyMessage: string;
  apiEndpoint: string;
  dialogTitle: string;
  dialogLabel: string;
}

export function ComboboxDinamis({
  options,
  value,
  onChange,
  onDataMasterChange,
  placeholder,
  searchPlaceholder,
  emptyMessage,
  apiEndpoint,
  dialogTitle,
  dialogLabel,
}: ComboboxDinamisProps) {
  const [open, setOpen] = useState(false);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const { toast } = useToast();

  const handleAddNew = async (newValue: string) => {
    try {
      const response = await fetch(apiEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ nama: newValue }),
      });
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.error || "Gagal menyimpan data baru.");
      }
      toast({
        title: "Berhasil!",
        description: `${dialogLabel} "${newValue}" berhasil ditambahkan.`,
      });
      await onDataMasterChange();
      onChange(newValue);
    } catch (error) {
      toast({
        title: "Error",
        description: (error as Error).message,
        variant: "destructive",
      });
    }
  };

  return (
    <>
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="outline"
            role="combobox"
            aria-expanded={open}
            className="w-full justify-between"
          >
            {value
              ? options.find((option) => option.nama.toLowerCase() === value.toLowerCase())?.nama
              : placeholder}
            <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-[--radix-popover-trigger-width] p-0 z-[99999]">
          <Command>
            <CommandInput placeholder={searchPlaceholder} />
            <CommandList>
                <CommandEmpty>{emptyMessage}</CommandEmpty>
                <CommandGroup>
                {options.map((option) => (
                    <CommandItem
                    key={option.id}
                    value={option.nama}
                    onSelect={(currentValue) => {
                        onChange(currentValue.toLowerCase() === value.toLowerCase() ? "" : currentValue);
                        setOpen(false);
                    }}
                    >
                    <Check
                        className={cn(
                        "mr-2 h-4 w-4",
                        value.toLowerCase() === option.nama.toLowerCase() ? "opacity-100" : "opacity-0"
                        )}
                    />
                    {option.nama}
                    </CommandItem>
                ))}
                </CommandGroup>
                <CommandSeparator />
                <CommandGroup>
                    <CommandItem
                        onSelect={() => {
                            setOpen(false);
                            setIsDialogOpen(true);
                        }}
                    >
                        <Plus className="mr-2 h-4 w-4" />
                        Tambah Baru
                    </CommandItem>
                </CommandGroup>
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
      <AddNewDialog
        isOpen={isDialogOpen}
        onClose={() => setIsDialogOpen(false)}
        onSave={handleAddNew}
        title={dialogTitle}
        label={dialogLabel}
      />
    </>
  );
} 
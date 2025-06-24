import * as React from "react";
import { Command, CommandInput, CommandItem, CommandList, CommandEmpty } from "@/components/ui/command";
import { cn } from "@/lib/utils";

interface ComboboxProps<T> {
  items: T[];
  value: string;
  onChange: (val: string) => void;
  placeholder?: string;
  getOptionLabel: (item: T) => string;
  getOptionValue: (item: T) => string;
  className?: string;
}

export function Combobox<T>({ items, value, onChange, placeholder, getOptionLabel, getOptionValue, className }: ComboboxProps<T>) {
  const [open, setOpen] = React.useState(false);
  const [search, setSearch] = React.useState("");
  const ref = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    if (open) document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  const selected = items.find(i => getOptionValue(i) === value);
  const filtered = items.filter(i => getOptionLabel(i).toLowerCase().includes(search.toLowerCase()));

  return (
    <div className={cn("relative", className)} ref={ref}>
      <button
        type="button"
        className={cn(
          "flex items-center w-full h-10 px-3 py-2 bg-gray-800 text-white border border-gray-300 rounded-md text-left",
          !selected && "text-gray-400"
        )}
        onClick={() => setOpen(v => !v)}
      >
        {selected ? getOptionLabel(selected) : (placeholder || "Pilih...")}
      </button>
      {open && (
        <div className="absolute z-50 mt-1 w-full bg-gray-800 border border-gray-300 rounded-b-md shadow-lg">
          <Command shouldFilter={false} className="bg-gray-800 text-white">
            <CommandInput
              placeholder={placeholder || "Cari..."}
              value={search}
              onValueChange={setSearch}
              className="bg-transparent text-white px-3 py-2 outline-none border-b border-gray-700"
              autoFocus
            />
            <CommandList className="max-h-48 overflow-auto">
              {filtered.length === 0 && <CommandEmpty>Tidak ada data</CommandEmpty>}
              {filtered.map(item => (
                <CommandItem
                  key={getOptionValue(item)}
                  value={getOptionValue(item)}
                  onSelect={() => {
                    onChange(getOptionValue(item));
                    setOpen(false);
                  }}
                  className="cursor-pointer px-3 py-2 hover:bg-gray-700"
                >
                  {getOptionLabel(item)}
                </CommandItem>
              ))}
            </CommandList>
          </Command>
        </div>
      )}
    </div>
  );
} 
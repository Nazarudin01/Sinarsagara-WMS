"use client";

import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface AddNewDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (value: string) => Promise<void>;
  title: string;
  label: string;
}

export function AddNewDialog({ isOpen, onClose, onSave, title, label }: AddNewDialogProps) {
  const [value, setValue] = useState("");
  const [isSaving, setIsSaving] = useState(false);

  const handleSave = async () => {
    if (!value.trim()) return;
    setIsSaving(true);
    await onSave(value);
    setIsSaving(false);
    setValue("");
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="z-[99999]">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        <div className="py-4">
          <Label htmlFor="name">{label}</Label>
          <Input
            id="name"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            className="mt-2"
            onKeyDown={(e) => { if(e.key === 'Enter') handleSave() }}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Batal</Button>
          <Button onClick={handleSave} disabled={isSaving || !value.trim()}>
            {isSaving ? "Menyimpan..." : "Simpan"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
} 
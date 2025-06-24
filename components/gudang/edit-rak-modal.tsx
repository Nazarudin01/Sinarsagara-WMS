"use client";

import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";

interface KodeRak {
  id: string;
  kode: string;
}

interface EditRakModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (newRakId: string) => void;
  availableRaks: KodeRak[];
  currentRakId: string | null;
}

export function EditRakModal({
  isOpen,
  onClose,
  onSubmit,
  availableRaks,
  currentRakId,
}: EditRakModalProps) {
  const [selectedRak, setSelectedRak] = useState(currentRakId || "");

  useEffect(() => {
    setSelectedRak(currentRakId || "");
  }, [currentRakId, isOpen]);

  const handleSubmit = () => {
    if (selectedRak && selectedRak !== currentRakId) {
      onSubmit(selectedRak);
    }
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit Kode Rak</DialogTitle>
        </DialogHeader>
        <div className="py-4">
          <Label htmlFor="kodeRak">Pilih Kode Rak Baru</Label>
          <Select value={selectedRak} onValueChange={setSelectedRak}>
            <SelectTrigger id="kodeRak">
              <SelectValue placeholder="Pilih rak..." />
            </SelectTrigger>
            <SelectContent>
              {availableRaks.map((rak) => (
                <SelectItem key={rak.id} value={rak.id}>
                  {rak.kode}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Batal
          </Button>
          <Button onClick={handleSubmit}>Simpan Perubahan</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
} 
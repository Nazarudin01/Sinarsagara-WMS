"use client";

import { useState, useRef } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Upload, Download, FileText, FileSpreadsheet, Paperclip } from "lucide-react";

interface ImportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImport: (file: File) => void;
}

export function StokMasukImportModal({ isOpen, onClose, onImport }: ImportModalProps) {
  const [file, setFile] = useState<File | null>(null);
  const [templateType, setTemplateType] = useState('excel');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files.length > 0) {
      setFile(event.target.files[0]);
    }
  };

  const handleDownloadTemplate = () => {
    window.location.href = `/api/stok-masuk/template?type=${templateType}`;
  };

  const handleImportClick = () => {
    if (file) {
      onImport(file);
    }
  };
  
  const handleSelectFileClick = () => {
    fileInputRef.current?.click();
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="z-[100]">
        <DialogHeader>
          <DialogTitle>Import Stok Masuk</DialogTitle>
        </DialogHeader>
        <div className="space-y-6 py-4">
          <div className="space-y-2">
            <h4 className="font-semibold">Download Template</h4>
            <p className="text-sm text-muted-foreground">
              Unduh template untuk memastikan format data sesuai.
            </p>
            <div className="flex items-center gap-2">
              <Select value={templateType} onValueChange={setTemplateType}>
                <SelectTrigger className="w-[120px]">
                  <SelectValue placeholder="Pilih Tipe" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="excel">
                    <div className="flex items-center gap-2">
                      <FileSpreadsheet className="h-4 w-4" /> Excel
                    </div>
                  </SelectItem>
                  <SelectItem value="csv">
                     <div className="flex items-center gap-2">
                      <FileText className="h-4 w-4" /> CSV
                    </div>
                  </SelectItem>
                </SelectContent>
              </Select>
              <Button onClick={handleDownloadTemplate} variant="outline">
                <Download className="mr-2 h-4 w-4" />
                Download
              </Button>
            </div>
          </div>

          <div className="space-y-2">
            <h4 className="font-semibold">Upload File</h4>
             <p className="text-sm text-muted-foreground">
              Pilih file Excel atau CSV yang sudah Anda isi.
            </p>
            <div className="flex items-center gap-2">
               <Input
                type="file"
                ref={fileInputRef}
                onChange={handleFileChange}
                accept=".xlsx, .csv"
                className="hidden"
              />
              <Button variant="outline" onClick={handleSelectFileClick}>
                <Paperclip className="mr-2 h-4 w-4" />
                Pilih File
              </Button>
              {file && <p className="text-sm text-muted-foreground truncate">{file.name}</p>}
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button onClick={onClose} variant="outline">Batal</Button>
          <Button onClick={handleImportClick} disabled={!file}>
            <Upload className="mr-2 h-4 w-4" />
            Import
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
} 
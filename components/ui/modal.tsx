import React from 'react';

interface ModalProps {
  terbuka: boolean;
  tutup: () => void;
  judul?: string;
  children: React.ReactNode;
}

export function Modal({ terbuka, tutup, judul, children }: ModalProps) {
  if (!terbuka) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Overlay semi-transparan */}
      <div
        className="absolute inset-0 bg-black bg-opacity-40"
        onClick={tutup}
      />
      {/* Konten modal */}
      <div className="relative bg-white rounded-2xl shadow-lg p-6 w-full max-w-lg z-50">
        {judul && <h2 className="text-xl font-bold mb-4 text-black">{judul}</h2>}
        {children}
        <button
          className="absolute top-2 right-2 text-gray-500 hover:text-black text-xl"
          onClick={tutup}
          aria-label="Tutup"
        >
          ×
        </button>
      </div>
    </div>
  );
} 
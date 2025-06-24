import React from "react";

export function Dialog({ open, onOpenChange, children }: any) {
  if (!open) return null;
  return <div>{children}</div>;
}

export function DialogContent({ children }: { children: React.ReactNode }) {
  return <div>{children}</div>;
}

export function DialogHeader({ children }: { children: React.ReactNode }) {
  return <div>{children}</div>;
}

export function DialogTitle({ children }: { children: React.ReactNode }) {
  return <h2>{children}</h2>;
} 
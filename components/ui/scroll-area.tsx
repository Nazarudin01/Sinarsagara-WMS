import React, { ReactNode } from "react";

interface ScrollAreaProps {
  children: ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

export const ScrollArea: React.FC<ScrollAreaProps> = ({ children, className = "", style = {} }) => {
  return (
    <div
      className={`overflow-auto ${className}`}
      style={{ maxHeight: "300px", ...style }}
    >
      {children}
    </div>
  );
}; 
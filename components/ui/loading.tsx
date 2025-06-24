import { motion } from 'framer-motion';

export function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <motion.div
        style={{ position: 'relative', width: '4rem', height: '4rem' }}
        animate={{
          rotate: 360,
        }}
        transition={{
          duration: 1.5,
          repeat: Infinity,
          ease: "linear",
        }}
      >
        <div className="absolute inset-0 border-4 border-primary rounded-full border-t-transparent"></div>
      </motion.div>
      <motion.div
        style={{ marginLeft: '1rem', fontSize: '1.125rem', fontWeight: 500, color: 'var(--muted-foreground)' }}
        animate={{
          opacity: [0.5, 1, 0.5],
        }}
        transition={{
          duration: 1.5,
          repeat: Infinity,
          ease: "easeInOut",
        }}
      >
        Memuat...
      </motion.div>
    </div>
  );
}

export function LoadingCard() {
  return (
    <motion.div
      style={{ padding: '1.5rem', borderRadius: '0.5rem', border: '1px solid var(--border-color)', background: 'var(--card-bg)' }}
      animate={{
        opacity: [0.5, 1, 0.5],
      }}
      transition={{
        duration: 1.5,
        repeat: Infinity,
        ease: "easeInOut",
      }}
    >
      <div className="space-y-3">
        <div className="h-4 bg-muted rounded w-3/4"></div>
        <div className="h-4 bg-muted rounded w-1/2"></div>
        <div className="h-4 bg-muted rounded w-2/3"></div>
      </div>
    </motion.div>
  );
}

export function LoadingChart() {
  return (
    <motion.div
      style={{ height: '400px', borderRadius: '0.5rem', border: '1px solid var(--border-color)', background: 'var(--card-bg)', padding: '1.5rem' }}
      animate={{
        opacity: [0.5, 1, 0.5],
      }}
      transition={{
        duration: 1.5,
        repeat: Infinity,
        ease: "easeInOut",
      }}
    >
      <div className="h-full flex items-center justify-center">
        <div className="w-12 h-12 border-4 border-primary rounded-full border-t-transparent animate-spin"></div>
      </div>
    </motion.div>
  );
}

export function LoadingTable() {
  return (
    <div className="rounded-lg border">
      <div className="p-4 border-b">
        <div className="h-4 bg-muted rounded w-1/4"></div>
      </div>
      <div className="p-4 space-y-3">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="flex space-x-4">
            <div className="h-4 bg-muted rounded w-1/4"></div>
            <div className="h-4 bg-muted rounded w-1/3"></div>
            <div className="h-4 bg-muted rounded w-1/4"></div>
          </div>
        ))}
      </div>
    </div>
  );
} 
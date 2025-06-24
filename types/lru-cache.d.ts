declare module 'lru-cache' {
  export class LRUCache<K, V> {
    constructor(options: {
      max?: number;
      maxAge?: number;
      updateAgeOnGet?: boolean;
      updateAgeOnHas?: boolean;
      allowStale?: boolean;
      dispose?: (value: V, key: K) => void;
      noDisposeOnSet?: boolean;
      ttl?: number;
      ttlResolution?: number;
      ttlAutopurge?: boolean;
      checkPeriod?: number;
      allowUnsafe?: boolean;
      maxEntrySize?: number;
      sizeCalculation?: (value: V, key: K) => number;
      noUpdateTTL?: boolean;
      updateAgeOnGet?: boolean;
      updateAgeOnHas?: boolean;
    });

    set(key: K, value: V): boolean;
    get(key: K): V | undefined;
    has(key: K): boolean;
    delete(key: K): boolean;
    clear(): void;
    keys(): K[];
    values(): V[];
    entries(): [K, V][];
    forEach(callback: (value: V, key: K, cache: LRUCache<K, V>) => void): void;
    size: number;
    max: number;
    maxAge: number;
    allowStale: boolean;
    length: number;
    itemCount: number;
  }
} 
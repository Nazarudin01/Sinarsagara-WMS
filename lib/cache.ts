import { LRUCache } from 'lru-cache';

const cache = new LRUCache<string, any>({
  max: 500, // Maximum number of items
  ttl: 1000 * 60 * 5, // Time to live: 5 minutes
});

export async function getCachedData<T>(
  key: string,
  fetchFn: () => Promise<T>,
  ttl?: number
): Promise<T> {
  const cached = cache.get(key);
  if (cached) {
    return cached as T;
  }

  const data = await fetchFn();
  cache.set(key, data);
  return data;
}

export function invalidateCache(key: string) {
  cache.delete(key);
}

export function clearCache() {
  cache.clear();
} 
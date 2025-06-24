'use client';

import { useState } from 'react';
import { useSession } from 'next-auth/react';
import { BellIcon, MagnifyingGlassIcon } from '@heroicons/react/24/outline';
import { useRouter } from 'next/navigation';

export default function Header() {
  const { data: session } = useSession();
  const router = useRouter();
  const [searchQuery, setSearchQuery] = useState('');

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      router.push(`/search?q=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  return (
    <header className="bg-white border-b border-wms-gray-light shadow-soft">
      <div className="px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Search Bar */}
          <form onSubmit={handleSearch} className="flex-1 max-w-2xl">
            <div className="relative">
              <input
                type="text"
                placeholder="Cari barang, transaksi, atau gudang..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 rounded-lg border border-wms-gray-light bg-white text-wms-gray-dark placeholder-wms-gray-dark focus:outline-none focus:ring-2 focus:ring-wms-green"
              />
              <MagnifyingGlassIcon className="absolute left-3 top-2.5 h-5 w-5 text-wms-gray-dark" />
            </div>
          </form>

          {/* Right Section */}
          <div className="flex items-center space-x-4 ml-4">
            {/* Notifications */}
            <button
              type="button"
              className="p-2 rounded-lg text-wms-gray-dark hover:text-wms-green-dark hover:bg-wms-green-light focus:outline-none focus:ring-2 focus:ring-wms-green"
            >
              <BellIcon className="h-6 w-6" />
              <span className="sr-only">Lihat notifikasi</span>
            </button>

            {/* User Profile */}
            <div className="flex items-center">
              <div className="text-right mr-3 hidden sm:block">
                <p className="text-sm font-medium text-wms-sidebar">{session?.user?.name}</p>
                <p className="text-xs text-wms-gray-dark">{session?.user?.email}</p>
              </div>
              <div className="h-8 w-8 rounded-full bg-wms-green flex items-center justify-center text-white font-medium">
                {session?.user?.name?.charAt(0).toUpperCase()}
              </div>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
} 
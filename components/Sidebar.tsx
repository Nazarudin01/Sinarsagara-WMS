"use client";

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { signOut } from 'next-auth/react';
import { useSession } from 'next-auth/react';
import {
  HomeIcon,
  BuildingStorefrontIcon,
  CubeIcon,
  ArrowLeftOnRectangleIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  ClipboardDocumentListIcon,
  ArrowsRightLeftIcon,
  ClipboardDocumentCheckIcon,
  UserGroupIcon,
  TruckIcon,
  ShoppingCartIcon,
} from '@heroicons/react/24/outline';

export default function Sidebar() {
  const pathname = usePathname();
  const { data: session } = useSession();
  const [openMaster, setOpenMaster] = useState(false);
  const [openTransaksi, setOpenTransaksi] = useState(false);
  const [openStok, setOpenStok] = useState(false);
  const [openLaporan, setOpenLaporan] = useState(false);

  const isActive = (path: string) => pathname === path;
  const isActiveGroup = (paths: string[]) => paths.some(path => pathname.startsWith(path));

  const menuItems = [
    {
      name: 'Dashboard',
      href: '/dashboard',
      icon: HomeIcon,
    },
    {
      name: 'Master Data',
      icon: CubeIcon,
      submenu: [
        { name: 'Barang', href: '/master-data/barang', icon: CubeIcon },
        { name: 'Kode Rak', href: '/master-data/kode-rak', icon: CubeIcon },
        { name: 'Pemasok', href: '/master-data/pemasok', icon: UserGroupIcon },
        { name: 'Pelanggan', href: '/master-data/pelanggan', icon: UserGroupIcon },
      ],
    },
    {
      name: 'Gudang',
      href: '/master/gudang',
      icon: BuildingStorefrontIcon,
    },
    {
      name: 'Stok',
      icon: CubeIcon,
      submenu: [
        { name: 'Stok Masuk', href: '/stok/masuk', icon: ShoppingCartIcon },
        { name: 'Stok Keluar', href: '/stok/keluar', icon: TruckIcon },
        { name: 'Stok Opname', href: '/opname', icon: ClipboardDocumentCheckIcon },
        { name: 'Transfer Gudang', href: '/transfer', icon: ArrowsRightLeftIcon },
      ],
    },
    {
      name: 'Transaksi',
      icon: ClipboardDocumentListIcon,
      submenu: [
        { name: 'Transaksi Barang Masuk', href: '/transaksi/masuk', icon: ShoppingCartIcon },
        { name: 'Transaksi Barang Keluar', href: '/transaksi/keluar', icon: TruckIcon },
      ],
    },
    {
      name: 'Laporan',
      icon: ClipboardDocumentListIcon,
      submenu: [
        { name: 'Laporan Stok', href: '/laporan/stok', icon: CubeIcon },
        { name: 'Laporan Transaksi', href: '/laporan/transaksi', icon: ClipboardDocumentListIcon },
      ],
    },
    {
      name: 'Pengaturan',
      href: '/pengaturan',
      icon: UserGroupIcon,
    },
  ];

  return (
    <aside className="w-64 bg-white flex flex-col h-screen shadow-lg" style={{ color: '#000' }}>
      <div className="p-6 border-b border-gray-300">
        <h1 className="text-2xl font-extrabold !text-black tracking-wide">PT Sinar Sagara Sejahtera</h1>
        <p className="text-sm !text-black/80 mt-1">Warehouse Management</p>
      </div>
      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {menuItems.map((item) => (
          <div key={item.name}>
            {item.href ? (
              <Link
                href={item.href}
                className={`flex items-center px-3 py-2 rounded-lg transition-colors font-semibold text-base !text-black ${
                  isActive(item.href)
                    ? 'bg-emerald-600 text-white shadow-md'
                    : '!text-black hover:bg-gray-200 hover:!text-black'
                }`}
              >
                <item.icon className="w-5 h-5 mr-3 !text-black" />
                {item.name}
              </Link>
            ) : (
              <div>
                <button
                  onClick={() => {
                    if (item.name === 'Master Data') setOpenMaster(!openMaster);
                    if (item.name === 'Stok') setOpenStok(!openStok);
                    if (item.name === 'Laporan') setOpenLaporan(!openLaporan);
                    if (item.name === 'Transaksi') setOpenTransaksi(!openTransaksi);
                  }}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg transition-colors font-semibold text-base !text-black ${
                    isActiveGroup(item.submenu?.map(s => s.href) || [])
                      ? 'bg-emerald-600 text-white shadow-md'
                      : '!text-black hover:bg-gray-200 hover:!text-black'
                  }`}
                >
                  <div className="flex items-center">
                    <item.icon className="w-5 h-5 mr-3 !text-black" />
                    {item.name}
                  </div>
                  {item.name === 'Master Data' ? (
                    openMaster ? <ChevronUpIcon className="w-4 h-4 !text-black" /> : <ChevronDownIcon className="w-4 h-4 !text-black" />
                  ) : item.name === 'Stok' ? (
                    openStok ? <ChevronUpIcon className="w-4 h-4 !text-black" /> : <ChevronDownIcon className="w-4 h-4 !text-black" />
                  ) : item.name === 'Laporan' ? (
                    openLaporan ? <ChevronUpIcon className="w-4 h-4 !text-black" /> : <ChevronDownIcon className="w-4 h-4 !text-black" />
                  ) : item.name === 'Transaksi' ? (
                    openTransaksi ? <ChevronUpIcon className="w-4 h-4 !text-black" /> : <ChevronDownIcon className="w-4 h-4 !text-black" />
                  ) : null}
                </button>
                <div
                  className={`ml-4 space-y-1 transition-all duration-200 ${
                    (item.name === 'Master Data' && openMaster) ||
                    (item.name === 'Stok' && openStok) ||
                    (item.name === 'Laporan' && openLaporan) ||
                    (item.name === 'Transaksi' && openTransaksi)
                      ? 'block'
                      : 'hidden'
                  }`}
                >
                  {item.submenu?.map((subItem) => (
                    <Link
                      key={subItem.name}
                      href={subItem.href}
                      className={`flex items-center px-3 py-2 rounded-lg transition-colors text-base !text-black ${
                        isActive(subItem.href)
                          ? 'bg-emerald-500/20 !text-emerald-700 shadow-sm'
                          : '!text-black hover:bg-gray-200 hover:!text-black'
                      }`}
                    >
                      <subItem.icon className="w-4 h-4 mr-3 !text-black" />
                      {subItem.name}
                    </Link>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </nav>
      <div className="p-4 border-t border-gray-300">
        <div className="mb-4">
          <p className="text-sm font-bold !text-black">{session?.user?.name}</p>
          <p className="text-xs !text-black/80">{session?.user?.email}</p>
        </div>
        <button
          onClick={() => signOut({ callbackUrl: '/login' })}
          className="w-full flex items-center justify-center px-3 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white transition-colors font-semibold"
        >
          <ArrowLeftOnRectangleIcon className="w-5 h-5 mr-2" />
          Keluar
        </button>
      </div>
    </aside>
  );
} 
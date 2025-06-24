"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from "@/components/ui/use-toast"
import { Package, Truck, Users, Warehouse, BarChart2, TrendingUp, Star, Activity } from 'lucide-react'
// @ts-ignore
import { Bar, Doughnut } from 'react-chartjs-2'
// @ts-ignore
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, ArcElement } from 'chart.js'
ChartJS.register(CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, ArcElement)

export default function DashboardPage() {
  const { toast } = useToast()
  const [stats, setStats] = useState({
    totalProducts: 0,
    totalSuppliers: 0,
    totalWarehouses: 0,
    totalStock: 0,
  })
  const [isLoading, setIsLoading] = useState(true)
  const [filter, setFilter] = useState<'harian'|'mingguan'|'bulanan'>('harian')
  const [chartData, setChartData] = useState<any>(null);
  const [chartLoading, setChartLoading] = useState(true);
  const [selectedDate, setSelectedDate] = useState<string>("");
  const [selectedWeek, setSelectedWeek] = useState<string>("");
  const [selectedMonth, setSelectedMonth] = useState<string>("");

  // Dummy data grafik
  const barData = {
    labels: ['Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu', 'Minggu'],
    datasets: [
      {
        label: 'Barang Masuk',
        backgroundColor: '#10b981',
        data: [12, 19, 3, 5, 2, 3, 7],
      },
      {
        label: 'Barang Keluar',
        backgroundColor: '#f87171',
        data: [8, 11, 7, 6, 4, 2, 5],
      },
    ],
  }
  const barOptions = {
    responsive: true,
    plugins: {
      legend: { position: 'top' },
      title: { display: false },
    },
  }
  const topBarangData = {
    labels: ['Barang A', 'Barang B', 'Barang C', 'Barang D', 'Barang E', 'Barang F', 'Barang G', 'Barang H', 'Barang I', 'Barang J'],
    datasets: [
      {
        label: 'Stok',
        data: [120, 110, 100, 90, 80, 70, 60, 50, 40, 30],
        backgroundColor: '#60a5fa',
      },
    ],
  }
  const gudangTrafikData = {
    labels: ['Gudang Utama', 'Gudang Cabang', 'Gudang 3'],
    datasets: [
      {
        label: 'Transaksi',
        data: [120, 80, 40],
        backgroundColor: ['#fbbf24', '#34d399', '#818cf8'],
      },
    ],
  }
  const barangKeluarData = {
    labels: ['Barang A', 'Barang B', 'Barang C', 'Barang D', 'Barang E'],
    datasets: [
      {
        label: 'Keluar',
        data: [50, 40, 35, 30, 25],
        backgroundColor: '#f87171',
      },
    ],
  }

  useEffect(() => {
    // Fetch stats dari API
    const fetchStats = async () => {
      try {
        const res = await fetch("/api/dashboard/stats");
        if (!res.ok) throw new Error("Gagal mengambil data statistik");
        const data = await res.json();
        setStats(data);
      } catch (error) {
        toast({
          title: "Error",
          description: "Gagal memuat data dashboard",
          variant: "destructive",
        });
      } finally {
        setIsLoading(false);
      }
    };
    fetchStats();
  }, [toast]);

  useEffect(() => {
    // Fetch chart data dari API
    setChartLoading(true);
    const params = new URLSearchParams();
    params.set("rentang", filter);
    if (filter === "harian" && selectedDate) params.set("tanggal", selectedDate);
    if (filter === "mingguan" && selectedWeek) params.set("minggu", selectedWeek);
    if (filter === "bulanan" && selectedMonth) params.set("bulan", selectedMonth);
    fetch(`/api/dashboard/charts?${params.toString()}`)
      .then(res => res.json())
      .then(res => setChartData(res))
      .finally(() => setChartLoading(false));
  }, [filter, selectedDate, selectedWeek, selectedMonth]);

  return (
    <div className="flex-1 space-y-6 p-6 bg-gray-50 min-h-screen">
      <h2 className="text-3xl font-bold tracking-tight text-gray-900 mb-4">Dashboard</h2>
      {/* Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-6 mb-6">
        <Card className="bg-white border-none shadow-md rounded-2xl flex flex-row items-center p-4">
          <div className="p-3 rounded-full bg-emerald-100 mr-4"><Package className="h-7 w-7 text-emerald-600" /></div>
          <div>
            <div className="text-lg font-bold text-gray-900">{stats.totalProducts}</div>
            <div className="text-xs text-gray-500 font-semibold">Total Barang Terdaftar</div>
          </div>
        </Card>
        <Card className="bg-white border-none shadow-md rounded-2xl flex flex-row items-center p-4">
          <div className="p-3 rounded-full bg-blue-100 mr-4"><Users className="h-7 w-7 text-blue-600" /></div>
          <div>
            <div className="text-lg font-bold text-gray-900">{stats.totalSuppliers}</div>
            <div className="text-xs text-gray-500 font-semibold">Total Supplier</div>
          </div>
        </Card>
        <Card className="bg-white border-none shadow-md rounded-2xl flex flex-row items-center p-4">
          <div className="p-3 rounded-full bg-yellow-100 mr-4"><Warehouse className="h-7 w-7 text-yellow-600" /></div>
          <div>
            <div className="text-lg font-bold text-gray-900">{stats.totalWarehouses}</div>
            <div className="text-xs text-gray-500 font-semibold">Total Gudang</div>
          </div>
        </Card>
        <Card className="bg-white border-none shadow-md rounded-2xl flex flex-row items-center p-4">
          <div className="p-3 rounded-full bg-purple-100 mr-4"><BarChart2 className="h-7 w-7 text-purple-600" /></div>
          <div>
            <div className="text-lg font-bold text-gray-900">{stats.totalStock}</div>
            <div className="text-xs text-gray-500 font-semibold">Total Stok Keseluruhan</div>
          </div>
        </Card>
      </div>
      {/* Grafik Barang Masuk vs Keluar */}
      <Card className="bg-white border-none shadow-md rounded-2xl p-6 mb-6">
        <div className="flex items-center justify-between mb-4 gap-2 flex-wrap">
          <div className="font-bold text-lg text-gray-900 flex items-center gap-2"><TrendingUp className="w-5 h-5 text-emerald-600" /> Grafik Barang Masuk vs Keluar</div>
          <div className="flex items-center gap-2">
            <select className="border rounded px-2 py-1 text-sm text-gray-900 bg-white" value={filter} onChange={e => setFilter(e.target.value as any)}>
              <option value="harian">Harian</option>
              <option value="mingguan">Mingguan</option>
              <option value="bulanan">Bulanan</option>
            </select>
            {filter === "harian" && (
              <input type="date" className="border rounded px-2 py-1 text-sm text-gray-900 bg-white" value={selectedDate} onChange={e => setSelectedDate(e.target.value)} />
            )}
            {filter === "mingguan" && (
              <input type="week" className="border rounded px-2 py-1 text-sm text-gray-900 bg-white" value={selectedWeek} onChange={e => setSelectedWeek(e.target.value)} />
            )}
            {filter === "bulanan" && (
              <input type="month" className="border rounded px-2 py-1 text-sm text-gray-900 bg-white" value={selectedMonth} onChange={e => setSelectedMonth(e.target.value)} />
            )}
          </div>
        </div>
        <div className="h-64">
          {chartLoading || !chartData ? (
            <div className="flex items-center justify-center h-full text-gray-400">Loading...</div>
          ) : (
            <Bar data={{
              labels: chartData.barangMasukKeluar.labels,
              datasets: [
                {
                  label: 'Barang Masuk',
                  backgroundColor: '#4ade80',
                  data: chartData.barangMasukKeluar.masuk,
                },
                {
                  label: 'Barang Keluar',
                  backgroundColor: '#60a5fa',
                  data: chartData.barangMasukKeluar.keluar,
                },
              ],
            }} options={{ responsive: true, plugins: { legend: { position: 'top' }, title: { display: false } } }} />
          )}
        </div>
      </Card>
      {/* 2 Kolom: Barang Terbanyak Keluar & 10 Barang Stok Terbanyak */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <Card className="bg-white border-none shadow-md rounded-2xl p-6">
          <div className="font-bold text-lg text-gray-900 flex items-center gap-2 mb-2"><Activity className="w-5 h-5 text-green-500" /> Barang Terbanyak Keluar</div>
          <div className="h-56">
            {chartLoading || !chartData ? (
              <div className="flex items-center justify-center h-full text-gray-400">Loading...</div>
            ) : (
              <Bar data={{
                labels: chartData.barangKeluarTerbanyak.labels,
                datasets: [{
                  label: 'Keluar',
                  data: chartData.barangKeluarTerbanyak.data,
                  backgroundColor: '#4ade80',
                }],
              }} options={{ responsive: true, plugins: { legend: { display: false } } }} />
            )}
          </div>
        </Card>
        <Card className="bg-white border-none shadow-md rounded-2xl p-6">
          <div className="font-bold text-lg text-gray-900 flex items-center gap-2 mb-2"><Star className="w-5 h-5 text-yellow-500" /> 10 Barang Stok Terbanyak</div>
          <div className="h-56">
            {chartLoading || !chartData ? (
              <div className="flex items-center justify-center h-full text-gray-400">Loading...</div>
            ) : (
              <Bar data={{
                labels: chartData.barangStokTerbanyak.labels,
                datasets: [{
                  label: 'Stok',
                  data: chartData.barangStokTerbanyak.data,
                  backgroundColor: '#60a5fa',
                }],
              }} options={{ responsive: true, plugins: { legend: { display: false } } }} />
            )}
          </div>
        </Card>
      </div>
      {/* Gudang Trafik Tertinggi */}
      <Card className="bg-white border-none shadow-md rounded-2xl p-6">
        <div className="font-bold text-lg text-gray-900 flex items-center gap-2 mb-2"><Warehouse className="w-5 h-5 text-blue-600" /> Gudang Trafik Tertinggi</div>
        <div className="h-64 flex items-center justify-center">
          {chartLoading || !chartData ? (
            <div className="flex items-center justify-center h-full text-gray-400">Loading...</div>
          ) : (
            <Doughnut data={{
              labels: chartData.gudangTrafik.labels,
              datasets: [{
                label: 'Transaksi',
                data: chartData.gudangTrafik.data,
                backgroundColor: ['#fbbf24', '#34d399', '#818cf8', '#f87171', '#60a5fa'],
              }],
            }} options={{ responsive: true, plugins: { legend: { position: 'bottom' } } }} />
          )}
        </div>
      </Card>
    </div>
  )
} 
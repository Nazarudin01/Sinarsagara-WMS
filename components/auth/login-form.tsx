'use client'

import { useState } from 'react'
import { signIn } from 'next-auth/react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { toast } from '@/components/ui/use-toast'

export default function LoginForm() {
  const router = useRouter()
  const [isLoading, setIsLoading] = useState(false)

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setIsLoading(true)

    const formData = new FormData(event.currentTarget)
    const email = formData.get('email') as string
    const password = formData.get('password') as string

    if (!email || !password) {
      toast({
        title: 'Error',
        description: 'Email dan password harus diisi',
        variant: 'destructive',
      })
      setIsLoading(false)
      return
    }

    try {
      console.log('Attempting login with:', { email }) // Logging untuk debug

      const result = await signIn('credentials', {
        email,
        password,
        redirect: false,
        callbackUrl: '/dashboard'
      })

      console.log('Login result:', result) // Logging untuk debug

      if (!result) {
        throw new Error('No result from signIn')
      }

      if (result.error) {
        toast({
          title: 'Error',
          description: result.error === 'CredentialsSignin' 
            ? 'Email atau password salah' 
            : result.error,
          variant: 'destructive',
        })
        return
      }

      if (result.ok) {
        toast({
          title: 'Success',
          description: 'Login berhasil',
        })
        router.push('/dashboard')
        router.refresh()
      }
    } catch (error) {
      console.error('Login error:', error) // Logging untuk debug
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Terjadi kesalahan saat login',
        variant: 'destructive',
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-6">
      <div className="space-y-2">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          name="email"
          type="email"
          autoComplete="email"
          required
          placeholder="nama@perusahaan.com"
          disabled={isLoading}
          className="w-full"
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          disabled={isLoading}
          className="w-full"
        />
      </div>
      <Button
        type="submit"
        className="w-full"
        disabled={isLoading}
      >
        {isLoading ? 'Loading...' : 'Login'}
      </Button>
    </form>
  )
} 
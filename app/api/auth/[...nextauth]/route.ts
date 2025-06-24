import { PrismaAdapter } from "@auth/prisma-adapter"
import { NextAuthOptions } from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"
import prisma from "@/lib/prisma"
import { compare } from "bcryptjs"
import NextAuth from "next-auth/next"

export const authOptions: NextAuthOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        console.log('Attempting to authorize with credentials:', { email: credentials?.email })
        
        if (!credentials?.email || !credentials?.password) {
          console.log('Missing credentials')
          throw new Error("Email dan password diperlukan")
        }

        const user = await prisma.user.findUnique({
          where: {
            email: credentials.email
          }
        })

        console.log('Found user:', user ? { id: user.id, email: user.email, role: user.role } : 'Not found')

        if (!user) {
          console.log('User not found')
          throw new Error("Email tidak ditemukan")
        }

        const isPasswordValid = await compare(
          credentials.password,
          user.password
        )

        console.log('Password validation result:', isPasswordValid)

        if (!isPasswordValid) {
          console.log('Invalid password')
          throw new Error("Password salah")
        }

        console.log('Authorization successful')
        return {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        }
      }
    })
  ],
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  pages: {
    signIn: "/login",
    error: "/login",
  },
  callbacks: {
    async jwt({ token, user }) {
      console.log('JWT Callback:', { token, user })
      if (user) {
        token.id = user.id
        token.role = user.role
      }
      return token
    },
    async session({ session, token }) {
      console.log('Session Callback:', { session, token })
      if (session.user) {
        session.user.id = token.id as string
        session.user.role = token.role as string
      }
      return session
    }
  },
  secret: process.env.NEXTAUTH_SECRET,
  debug: true, // Enable debug mode
}

const handler = NextAuth(authOptions)
export { handler as GET, handler as POST } 
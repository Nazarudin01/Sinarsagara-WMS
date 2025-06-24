import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import prisma from "@/lib/prisma";
import { compare } from "bcrypt";
import { Role } from "@prisma/client";
import { rateLimit } from "@/lib/rate-limit";

export const authOptions: NextAuthOptions = {
  session: {
    strategy: "jwt",
    maxAge: 30 * 24 * 60 * 60, // 30 hari
  },
  pages: {
    signIn: "/login",
    error: "/login",
    signOut: "/login",
  },
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Email dan password harus diisi");
        }

        // Rate limiting
        const limiter = await rateLimit(credentials.email);
        if (!limiter.success) {
          throw new Error("Terlalu banyak percobaan login. Silakan coba lagi nanti.");
        }

        try {
          const user = await prisma.user.findUnique({
            where: {
              email: credentials.email,
              isActive: true
            }
          });

          if (!user) {
            throw new Error("Email atau password salah");
          }

          const isPasswordValid = await compare(
            credentials.password,
            user.password
          );

          if (!isPasswordValid) {
            throw new Error("Email atau password salah");
          }

          // Log successful login
          await prisma.loginLog.create({
            data: {
              userId: user.id,
              email: user.email,
              status: "SUCCESS",
              ipAddress: "N/A", // Will be added in production
              userAgent: "N/A" // Will be added in production
            }
          });

          return {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
          };
        } catch (error) {
          // Log failed login attempt
          if (error instanceof Error) {
            await prisma.loginLog.create({
              data: {
                email: credentials.email,
                status: "FAILED",
                ipAddress: "N/A",
                userAgent: "N/A",
                errorMessage: error.message
              }
            });
          }
          throw error;
        }
      }
    })
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.role = user.role;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.id as string;
        session.user.role = token.role as Role;
      }
      return session;
    },
    async redirect({ url, baseUrl }) {
      // Jika URL adalah URL relatif, tambahkan baseUrl
      if (url.startsWith("/")) return `${baseUrl}${url}`;
      // Jika URL adalah URL absolut yang sama dengan baseUrl, izinkan
      else if (new URL(url).origin === baseUrl) return url;
      // Default ke dashboard
      return baseUrl + "/dashboard";
    },
  },
  secret: process.env.NEXTAUTH_SECRET,
  debug: process.env.NODE_ENV === "development",
}; 
// NEXT.JS FULL PROJECT (MULTI-FILE IN SINGLE DOCUMENT)
// Semua file dipisahkan dengan komentar ===========================
// Anda dapat memecahnya ke folder masing-masing saat download.

/*
===================================================================
📁 PROYEK NEXT.JS — MEDTECH ELEKTRONIK
===================================================================
Struktur Folder:

/app
  ├── layout.tsx
  ├── page.tsx
  ├── products/page.tsx
  ├── cart/page.tsx
  ├── checkout/page.tsx
  ├── login/page.tsx
  ├── register/page.tsx
  ├── admin/products/page.tsx
  └── admin/orders/page.tsx

/api
  ├── products/route.ts
  ├── auth/login/route.ts
  ├── auth/register/route.ts
  ├── cart/route.ts
  └── orders/route.ts

/components
  ├── Navbar.tsx
  ├── Footer.tsx
  ├── ProductCard.tsx
  ├── ProductList.tsx
  ├── AdminSidebar.tsx
  └── Input.tsx

/lib
  ├── db.ts
  ├── auth.ts
  └── utils.ts

/public
  └── logo.png

===================================================================
*/

// ===================================================================
// FILE: app/layout.tsx
// ===================================================================
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-[#f7f4fb] text-[#1a1a1a]">
        {children}
      </body>
    </html>
  );
}

// ===================================================================
// FILE: app/page.tsx (Homepage)
// ===================================================================
import Navbar from "../components/Navbar";
import ProductList from "../components/ProductList";

export default function HomePage() {
  return (
    <div>
      <Navbar />
      <section className="p-6 text-center bg-[#ffffff]/80 backdrop-blur-xl shadow-[0_4px_20px_rgba(107,76,230,0.08)]-xl border border-[#e7e2f5] shadow-[0_4px_20px_rgba(107,76,230,0.08)]">
        <h1 className="text-4xl font-bold mb-2">MedTech Elektronik</h1>
        <p className="text-lg text-[#6a6a7c]">Elektronik Modern • Keamanan • Aksesoris</p>
      </section>
      <ProductList />
    </div>
  );
}

// ===================================================================
// FILE: components/Navbar.tsx
// ===================================================================
export default function Navbar() {
  return (
    <nav className="w-full bg-[#ffffff]/80 backdrop-blur-xl border-b border-[#e7e2f5] p-4 flex justify-between items-center shadow-[0_4px_20px_rgba(107,76,230,0.08)]-sm">
      <h1 className="font-bold text-xl text-[#6b4ce6]">MedTech Store</h1>
      <div className="flex gap-4">
        <a href="/products">Produk</a>
        <a href="/cart">Cart</a>
        <a href="/login">Login</a>
      </div>
    </nav>
  );
}

// ===================================================================
// FILE: components/ProductCard.tsx
// ===================================================================
export default function ProductCard({ product }) {
  return (
    <div className="border rounded-xl p-4 shadow-[0_4px_20px_rgba(107,76,230,0.08)] bg-[#ffffff]/80 backdrop-blur-xl shadow-[0_4px_20px_rgba(107,76,230,0.08)]-xl border border-[#e7e2f5]">
      <img src={product.image} className="rounded mb-3" />
      <h2 className="font-semibold text-lg">{product.name}</h2>
      <p className="text-gray-500">Rp {product.price.toLocaleString()}</p>
      <button className="mt-2 bg-[#6b4ce6] hover:bg-[#583ad6] transition-all text-white px-4 py-2 rounded">Tambah</button>
    </div>
  );
}

// ===================================================================
// FILE: components/ProductList.tsx
// ===================================================================
import ProductCard from "./ProductCard";

const products = [
  { id: 1, name: "Kamera CCTV", price: 450000, image: "/cctv.jpg" },
  { id: 2, name: "Alarm Sensor", price: 350000, image: "/alarm.jpg" },
];

export default function ProductList() {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-4 p-6">
      {products.map((p) => (
        <ProductCard key={p.id} product={p} />
      ))}
    </div>
  );
}

// ===================================================================
// FILE: lib/db.ts (Database Mock - nanti bisa upgrade ke PostgreSQL)
// ===================================================================
export const db = {
  users: [],
  products: [],
  orders: []
};

// ===================================================================
// FILE: api/products/route.ts
// ===================================================================
import { NextResponse } from "next/server";
import { db } from "../../../lib/db";

export async function GET() {
  return NextResponse.json(db.products);
}

export async function POST(req) {
  const data = await req.json();
  db.products.push(data);
  return NextResponse.json({ success: true });
}

// ===================================================================
// FILE: api/auth/register/route.ts
// ===================================================================
import { db } from "../../../../lib/db";
import { NextResponse } from "next/server";

export async function POST(req) {
  const body = await req.json();
  db.users.push(body);
  return NextResponse.json({ success: true });
}

// ===================================================================
// FILE: api/auth/login/route.ts
// ===================================================================
import { db } from "../../../../lib/db";
import { NextResponse } from "next/server";

export async function POST(req) {
  const { email, password } = await req.json();
  const user = db.users.find(u => u.email === email && u.password === password);
  return NextResponse.json({ success: !!user, user });
}

// ===================================================================
// FILE: api/orders/route.ts
// ===================================================================
import { db } from "../../../lib/db";
import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json(db.orders);
}

export async function POST(req) {
  const body = await req.json();
  db.orders.push(body);
  return NextResponse.json({ success: true });
}

// ===================================================================
// FILE: app/products/page.tsx
// ===================================================================
import Navbar from "../../components/Navbar";
import ProductList from "../../components/ProductList";

export default function ProductsPage() {
  return (
    <div>
      <Navbar />
      <h1 className="text-3xl font-bold p-6">Semua Produk</h1>
      <ProductList />
    </div>
  );
}

// ===================================================================
// FILE: app/cart/page.tsx
// ===================================================================
import Navbar from "../../components/Navbar";

export default function CartPage() {
  return (
    <div>
      <Navbar />
      <h1 className="text-3xl font-bold p-6">Keranjang Belanja</h1>
      <p className="p-6 text-[#6a6a7c]">Fitur keranjang akan disempurnakan pada tahap backend.</p>
    </div>
  );
}

// ===================================================================
// FILE: app/login/page.tsx
// ===================================================================
import Navbar from "../../components/Navbar";

export default function LoginPage() {
  return (
    <div>
      <Navbar />
      <div className="max-w-md mx-auto p-6 bg-[#ffffff]/80 backdrop-blur-xl shadow-[0_4px_20px_rgba(107,76,230,0.08)]-xl border border-[#e7e2f5] shadow-[0_4px_20px_rgba(107,76,230,0.08)] rounded">
        <h1 className="text-2xl font-bold mb-4">Login</h1>
        <form className="flex flex-col gap-4">
          <input placeholder="Email" className="p-2 border rounded" />
          <input placeholder="Password" type="password" className="p-2 border rounded" />
          <button className="bg-[#6b4ce6] hover:bg-[#583ad6] transition-all text-white py-2 rounded">Masuk</button>
        </form>
      </div>
    </div>
  );
}

// ===================================================================
// FILE: api/cart/route.ts
// ===================================================================
import { db } from "../../../lib/db";
import { NextResponse } from "next/server";

export async function GET() {
  return NextResponse.json(db.cart || []);
}

export async function POST(req) {
  const body = await req.json();
  db.cart = body;
  return NextResponse.json({ success: true });
}



// ===================================================================
// STEP 1: AUTH SYSTEM (JWT + BCRYPT)
// ===================================================================

// ===================================================================
// FILE: lib/auth.ts
// ===================================================================
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const SECRET = "MEDTECH_SUPER_SECRET_KEY"; // Ganti dengan env variable di production

export async function hashPassword(password: string) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}

export async function comparePassword(password: string, hash: string) {
  return bcrypt.compare(password, hash);
}

export function createToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, {
    expiresIn: "7d",
  });
}

export function verifyToken(token: string) {
  try {
    return jwt.verify(token, SECRET);
  } catch {
    return null;
  }
}

// ===================================================================
// FILE: api/auth/register/route.ts (UPDATED WITH HASH)
// ===================================================================
import { db } from "../../../../lib/db";
import { NextResponse } from "next/server";
import { hashPassword } from "../../../../lib/auth";

export async function POST(req) {
  const body = await req.json();

  const hashed = await hashPassword(body.password);

  const user = {
    id: Date.now(),
    email: body.email,
    password: hashed,
    role: "user",
  };

  db.users.push(user);

  return NextResponse.json({ success: true, user: { id: user.id, email: user.email } });
}

// ===================================================================
// FILE: api/auth/login/route.ts (UPDATED FOR JWT)
// ===================================================================
import { comparePassword, createToken } from "../../../../lib/auth";

export async function POST(req) {
  const { email, password } = await req.json();

  const user = db.users.find((u) => u.email === email);
  if (!user) return NextResponse.json({ success: false, message: "User tidak ditemukan" }, { status: 400 });

  const match = await comparePassword(password, user.password);
  if (!match) return NextResponse.json({ success: false, message: "Password salah" }, { status: 400 });

  const token = createToken(user);

  return NextResponse.json({ success: true, token, user: { id: user.id, email: user.email, role: user.role } });
}

// ===================================================================
// STEP 2: BACKEND — PRODUCT CRUD API
// ===================================================================

// ===================================================================
// FILE: api/products/[id]/route.ts
// ===================================================================
import { NextResponse } from "next/server";
import { db } from "../../../../lib/db";

export async function PUT(req, { params }) {
  const id = Number(params.id);
  const data = await req.json();

  const index = db.products.findIndex((p) => p.id === id);
  if (index === -1) return NextResponse.json({ success: false }, { status: 404 });

  db.products[index] = { ...db.products[index], ...data };
  return NextResponse.json({ success: true, product: db.products[index] });
}

export async function DELETE(req, { params }) {
  const id = Number(params.id);
  db.products = db.products.filter((p) => p.id !== id);

  return NextResponse.json({ success: true });
}



// ===================================================================
// FILE: app/products/[id]/page.tsx  (Product Detail — Style C Marketplace)
// ===================================================================
import Navbar from "../../../components/Navbar";

async function getProduct(id: string) {
  const res = await fetch(`${process.env.NEXT_PUBLIC_BASE_URL}/api/products/${id}`);
  return res.json();
}

export default async function ProductDetail({ params }) {
  const product = await getProduct(params.id);

  return (
    <div>
      <Navbar />
      <div className="p-6 max-w-5xl mx-auto grid md:grid-cols-2 gap-6">

        {/* IMAGE AREA */}
        <div className="bg-white/80 backdrop-blur-xl border border-[#e7e2f5] rounded-xl shadow-[0_4px_20px_rgba(107,76,230,0.08)] p-4">
          <img src={product.image} className="w-full rounded-lg mb-4" />
          <div className="grid grid-cols-4 gap-2">
            {[1,2,3,4].map((i) => (
              <div key={i} className="aspect-square bg-[#eee] rounded-lg"></div>
            ))}
          </div>
        </div>

        {/* INFO AREA */}
        <div className="flex flex-col gap-4">
          <h1 className="text-3xl font-bold text-[#1a1a1a]">{product.name}</h1>
          <p className="text-xl font-semibold text-[#6b4ce6]">Rp {product.price?.toLocaleString()}</p>
          <p className="text-[#6a6a7c] leading-relaxed">{product.description || "Deskripsi produk belum tersedia."}</p>

          <div className="flex gap-3 mt-4">
            <button className="bg-[#6b4ce6] hover:bg-[#583ad6] text-white rounded-xl py-3 px-6 text-lg w-full">Tambah ke Keranjang</button>
            <button className="bg-black text-white rounded-xl py-3 px-6 text-lg w-full">Beli Sekarang</button>
          </div>
        </div>

      </div>
    </div>
  );
}


// ===================================================================
// FILE: app/cart/page.tsx  (Cart Page)
// ===================================================================
import Navbar from "../../components/Navbar";

export default function CartPage() {
  const cart = [];

  return (
    <div>
      <Navbar />
      <div className="max-w-5xl mx-auto p-6">
        <h1 className="text-3xl font-bold mb-6">Keranjang</h1>
        {cart.length === 0 ? (
          <p className="text-gray-500">Keranjang masih kosong.</p>
        ) : (
          <div>Keranjang item list...</div>
        )}
      </div>
    </div>
  );
}


// ===================================================================
// FILE: lib/supabase.ts  (Supabase Client)
// ===================================================================
import { createClient } from '@supabase/supabase-js';

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);

// ===================================================================
// FILE: app/api/auth/register/route.ts  (Register API)
// ===================================================================
import { supabase } from '@/lib/supabase';
import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  const { email, password } = await req.json();

  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });

  return NextResponse.json({ user: data.user });
}

// ===================================================================
// FILE: app/api/auth/login/route.ts  (Login API)
// ===================================================================
import { NextResponse } from 'next/server';
import { supabase } from '@/lib/supabase';

export async function POST(req: Request) {
  const { email, password } = await req.json();
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });

  if (error) return NextResponse.json({ error: error.message }, { status: 400 });
  return NextResponse.json({ user: data.user, session: data.session });
}

// ===================================================================
// FILE: app/admin/products/page.tsx  (Admin Panel Produk)
// ===================================================================
'use client';
import { useEffect, useState } from 'react';
import Navbar from '@/components/Navbar';

export default function AdminProducts() {
  const [products, setProducts] = useState([]);
  const [name, setName] = useState('');
  const [price, setPrice] = useState('');
  const [image, setImage] = useState('');

  const addProduct = async () => {
    await fetch('/api/products', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, price, image }),
    });
    setName(''); setPrice(''); setImage('');
    loadProducts();
  };

  const loadProducts = async () => {
    const res = await fetch('/api/products');
    const data = await res.json();
    setProducts(data);
  };

  useEffect(() => { loadProducts(); }, []);

  return (
    <div>
      <Navbar />
      <div className="max-w-4xl mx-auto p-6">
        <h1 className="text-3xl font-bold mb-6">Admin - Produk</h1>

        <div className="grid gap-4 p-4 bg-white rounded-xl shadow">
          <input className="border p-2" placeholder="Nama" value={name} onChange={e=>setName(e.target.value)} />
          <input className="border p-2" placeholder="Harga" value={price} onChange={e=>setPrice(e.target.value)} />
          <input className="border p-2" placeholder="Image URL" value={image} onChange={e=>setImage(e.target.value)} />
          <button onClick={addProduct} className="bg-black text-white py-2 rounded-lg">Tambah Produk</button>
        </div>

        <div className="mt-6 grid gap-4">
          {products.map((p:any) => (
            <div key={p.id} className="border p-4 rounded-xl flex justify-between">
              <div>
                <h2 className="font-bold">{p.name}</h2>
                <p>Rp {p.price}</p>
              </div>
              <img src={p.image} className="w-16 h-16 rounded" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ===================================================================
// FILE: app/api/products/route.ts  (Products API - List + Add)
// ===================================================================
import { supabase } from '@/lib/supabase';
import { NextResponse } from 'next/server';

export async function GET() {
  const { data } = await supabase.from('products').select('*');
  return NextResponse.json(data);
}

export async function POST(req: Request) {
  const body = await req.json();
  const { data, error } = await supabase.from('products').insert([body]);
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });
  return NextResponse.json(data);
}


// ===================================================================
// FILE: app/api/cart/route.ts  (Cart API — Add / Remove / Update)
// ===================================================================
import { supabase } from '@/lib/supabase';
import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  const body = await req.json();
  const { data, error } = await supabase.from('cart').insert([body]);
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });
  return NextResponse.json(data);
}

export async function PUT(req: Request) {
  const body = await req.json();
  const { id, qty } = body;
  const { data, error } = await supabase.from('cart').update({ qty }).eq('id', id);
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });
  return NextResponse.json(data);
}

export async function DELETE(req: Request) {
  const body = await req.json();
  const { id } = body;
  const { error } = await supabase.from('cart').delete().eq('id', id);
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });
  return NextResponse.json({ success: true });
}

// ===================================================================
// FILE: app/checkout/page.tsx  (Checkout Page)
// ===================================================================
import Navbar from "../../components/Navbar";

export default function CheckoutPage() {
  return (
    <div>
      <Navbar />
      <div className="max-w-4xl mx-auto p-6">
        <h1 className="text-3xl font-bold mb-4">Checkout</h1>
        <div className="bg-white p-6 rounded-xl shadow">
          <p className="text-gray-600">Ringkasan belanja akan tampil di sini.</p>
        </div>
      </div>
    </div>
  );
}

// ===================================================================
// FILE: app/api/orders/route.ts  (Create Order API)
// ===================================================================
import { supabase } from '@/lib/supabase';
import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  const body = await req.json();
  const { data, error } = await supabase.from('orders').insert([body]);
  if (error) return NextResponse.json({ error: error.message }, { status: 400 });
  return NextResponse.json(data);
}

// ===================================================================
// FILE: app/order-success/page.tsx
// ===================================================================
import Navbar from "../components/Navbar";

export default function OrderSuccess() {
  return (
    <div>
      <Navbar />
      <div className="text-center p-20">
        <h1 className="text-4xl font-bold text-green-600">Pembayaran Berhasil</h1>
        <p className="text-gray-600 mt-3">Terima kasih telah berbelanja.</p>
      </div>
    </div>
  );
}

// ===================================================================
// FILE: app/login/page.tsx  (Login UI)
// ===================================================================
'use client';
import { useState } from 'react';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const login = async () => {
    await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
  };

  return (
    <div className="max-w-md mx-auto p-6 mt-10 bg-white rounded-xl shadow">
      <h1 className="text-3xl font-bold mb-4 text-center">Login</h1>
      <input className="border p-3 w-full mb-3" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
      <input className="border p-3 w-full mb-3" placeholder="Password" value={password} type="password" onChange={e => setPassword(e.target.value)} />
      <button onClick={login} className="bg-black text-white w-full py-3 rounded-lg">Masuk</button>
    </div>
  );
}

// ===================================================================
// FILE: app/register/page.tsx  (Register UI)
// ===================================================================
'use client';
import { useState } from 'react';

export default function RegisterPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const register = async () => {
    await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
  };

  return (
    <div className="max-w-md mx-auto p-6 mt-10 bg-white rounded-xl shadow">
      <h1 className="text-3xl font-bold mb-4 text-center">Register</h1>
      <input className="border p-3 w-full mb-3" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
      <input className="border p-3 w-full mb-3" placeholder="Password" value={password} type="password" onChange={e => setPassword(e.target.value)} />
      <button onClick={register} className="bg-black text-white w-full py-3 rounded-lg">Daftar</button>
    </div>
  );
}

// ===================================================================
// FILE: vercel.json  (Deployment Config for Vercel)
// ===================================================================
{
  "version": 2,
  "builds": [{ "src": "next.config.js", "use": "@vercel/next" }],
  "env": {
    "NEXT_PUBLIC_SUPABASE_URL": "YOUR_SUPABASE_URL",
    "NEXT_PUBLIC_SUPABASE_ANON_KEY": "YOUR_SUPABASE_ANON_KEY",
    "MIDTRANS_SERVER_KEY": "YOUR_SERVER_KEY",
    "MIDTRANS_CLIENT_KEY": "YOUR_CLIENT_KEY"
  }
}

// ===================================================================
// FILE: app/api/payment/route.ts  (Midtrans Snap Token Generator)
// ===================================================================
import { NextResponse } from 'next/server';
import crypto from 'crypto';

export async function POST(req: Request) {
  const body = await req.json();
  const { order_id, amount } = body;

  const serverKey = process.env.MIDTRANS_SERVER_KEY!;
  const authHeader = Buffer.from(serverKey + ':').toString('base64');

  const snapReq = await fetch('https://app.sandbox.midtrans.com/snap/v1/transactions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Basic ${authHeader}`,
    },
    body: JSON.stringify({
      transaction_details: {
        order_id,
        gross_amount: amount,
      }
    })
  });

  const snapData = await snapReq.json();
  return NextResponse.json(snapData);
}

// ===================================================================
// FILE: app/checkout/page.tsx  (Updated Checkout with Midtrans SNAP)
// ===================================================================
'use client';
import { useState } from 'react';
import Navbar from '../../components/Navbar';

export default function Checkout() {
  const [loading, setLoading] = useState(false);

  const payNow = async () => {
    setLoading(true);

    const res = await fetch('/api/payment', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ order_id: Date.now().toString(), amount: 200000 })
    });

    const data = await res.json();
    setLoading(false);
    window.location.href = data.redirect_url;
  };

  return (
    <div>
      <Navbar />
      <div className="max-w-3xl mx-auto p-6">
        <h1 className="text-3xl font-bold mb-6">Checkout</h1>

        <div className="bg-white p-6 rounded-xl shadow">
          <p className="text-gray-600 mb-4">Total Pembayaran: <strong>Rp 200.000</strong></p>
          <button onClick={payNow} className="bg-black text-white w-full py-3 rounded-xl" disabled={loading}>
            {loading ? 'Menghubungkan ke Midtrans...' : 'Bayar Sekarang'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ===================================================================
// FILE: middleware.ts (Protect Admin Pages)
// ===================================================================
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(req: NextRequest) {
  const session = req.cookies.get('sb-access-token');

  // Protect admin route
  if (req.nextUrl.pathname.startsWith('/admin')) {
    if (!session) {
      return NextResponse.redirect(new URL('/login', req.url));
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/admin/:path*']
};

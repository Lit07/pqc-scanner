import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function proxy(request: NextRequest) {
  const token = request.cookies.get('auth_token')?.value;
  
  const isAuthPage = request.nextUrl.pathname.startsWith('/login') || 
                     request.nextUrl.pathname.startsWith('/register') || 
                     request.nextUrl.pathname.startsWith('/verify');
                     
  const isProtectedPage = request.nextUrl.pathname.startsWith('/dashboard') ||
                          request.nextUrl.pathname.startsWith('/inventory') ||
                          request.nextUrl.pathname.startsWith('/discovery') ||
                          request.nextUrl.pathname.startsWith('/scan')      ||
                          request.nextUrl.pathname.startsWith('/cbom')      ||
                          request.nextUrl.pathname.startsWith('/pqc')       ||
                          request.nextUrl.pathname.startsWith('/rating');

  if (isAuthPage && token) {
    return NextResponse.redirect(new URL('/dashboard', request.url));
  }

  if (isProtectedPage && !token) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*', '/inventory/:path*', '/discovery/:path*', '/scan/:path*', '/cbom/:path*', '/pqc/:path*', '/rating/:path*', '/login', '/register', '/verify'],
};

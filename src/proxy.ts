import { NextResponse } from 'next/server';
import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';

import { isSearchEngineCrawler } from './lib/utils/crawlerDetection';
import { logger } from './lib/utils/logger';

// All paths that should be considered public and bypass the main authentication flow
const PUBLIC_PATHS_MATCHER = [
  '/',
  '/review(.*)',
  '/contest(.*)',
  '/leaderboards(.*)',
  '/sign-in(.*)',
  '/sign-up(.*)',
  '/sign-out(.*)',
  '/invite(.*)',
  '/sitemap.xml',
  '/robots.txt',
  '/restaurants/(.*)',
  '/dishes/(.*)',
  // Public API routes
  '/api/webhooks/clerk',
  '/api/geocode',
  '/api/access-request',
  '/api/stripe-webhook',
  '/api/visits/public',
  '/api/user/unsubscribe',
  '/api/contest',
  '/api/leaderboards',
];

const isPublicRoute = createRouteMatcher(PUBLIC_PATHS_MATCHER);
const isApiRoute = (pathname: string) => pathname.startsWith('/api/');

/**
 * Helper function to add CORS headers to a response in-place
 */
function addCorsHeaders(response: NextResponse, origin: string | null, host: string | null): void {
  const allowedOrigins = [
    host ? `https://${host}` : null,
    'http://localhost:3000',
    'http://localhost:3001',
  ].filter(Boolean) as string[];

  response.headers.set(
    'Access-Control-Allow-Origin',
    origin && allowedOrigins.includes(origin) ? origin : 'null'
  );
  response.headers.set('Access-Control-Allow-Credentials', 'true');
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  response.headers.set(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Requested-With'
  );
}

/**
 * Special case: /api/invite/[code] is public (for validation), but /api/invite/index and /api/invite/store-pending remain protected
 */
function isInviteCodeValidation(pathname: string): boolean {
  return (
    pathname.startsWith('/api/invite/') &&
    pathname !== '/api/invite/index' &&
    pathname !== '/api/invite/store-pending'
  );
}

/**
 * Next.js middleware using clerkMiddleware wrapper
 * This ensures Clerk can detect middleware usage for getAuth() to work in API routes
 */
export default clerkMiddleware(async (auth, req) => {
  const pathname = req.nextUrl.pathname;
  const origin = req.headers.get('origin');
  const host = req.headers.get('host');

  // CORS Configuration
  const allowedOrigins = [
    host ? `https://${host}` : null,
    'http://localhost:3000',
    'http://localhost:3001',
  ].filter(Boolean) as string[];

  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    const corsHeaders = {
      'Access-Control-Allow-Origin': origin && allowedOrigins.includes(origin) ? origin : 'null',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
      'Access-Control-Allow-Credentials': 'true',
      'Access-Control-Max-Age': '86400',
    };
    return new NextResponse(null, { status: 200, headers: corsHeaders });
  }

  // Handle API routes first - call auth() for ALL API routes to set up Clerk's context
  // This is essential for getAuth() to detect clerkMiddleware() was used
  if (isApiRoute(pathname)) {
    let userId: string | null = null;
    let sessionId: string | null = null;

    try {
      const authResult = await auth();
      userId = authResult.userId;
      sessionId = authResult.sessionId;
    } catch (authError) {
      // Continue - auth() may fail for unauthenticated requests, but context is still set up
      logger.warn('Error calling auth() for API route', {
        pathname,
        error: authError instanceof Error ? authError.message : 'Unknown error',
      });
    }

    const isPublicApiRoute = isPublicRoute(req) || isInviteCodeValidation(pathname);

    // For public API routes, allow through without authentication enforcement
    // Don't pass request object to NextResponse.next() - preserves Clerk's internal markers
    if (isPublicApiRoute) {
      const response = NextResponse.next();
      addCorsHeaders(response, origin, host);
      return response;
    }

    // For protected API routes, enforce authentication
    if (!userId) {
      const apiUnauthorizedResponse = NextResponse.next();
      addCorsHeaders(apiUnauthorizedResponse, origin, host);
      return apiUnauthorizedResponse;
    }

    // Protected API route with authentication
    // Don't pass request object to NextResponse.next() - preserves Clerk's internal markers
    const response = NextResponse.next();
    addCorsHeaders(response, origin, host);
    return response;
  }

  // Handle non-API routes
  // Check if public first (before calling auth)
  if (isPublicRoute(req) || isInviteCodeValidation(pathname)) {
    // Handle crawlers for public content routes
    const userAgent = req.headers.get('user-agent');
    const isCrawler = isSearchEngineCrawler(userAgent);
    const isPublicContentRoute =
      pathname.startsWith('/restaurants/') || pathname.startsWith('/dishes/');

    if (isCrawler && isPublicContentRoute) {
      const response = NextResponse.next({
        request: {
          headers: req.headers,
        },
      });
      response.headers.set('X-Robots-Tag', 'index, follow');
      addCorsHeaders(response, origin, host);
      return response;
    }

    const response = NextResponse.next({
      request: {
        headers: req.headers,
      },
    });
    addCorsHeaders(response, origin, host);
    return response;
  }

  // For protected non-API routes, call auth() and check authentication
  let userId: string | null = null;
  try {
    const authResult = await auth();
    userId = authResult.userId;
  } catch (authError) {
    // Continue - auth() may fail for unauthenticated requests
  }

  // Redirect unauthenticated users to sign-in
  if (!userId) {
    const urlOrigin = `${req.nextUrl.protocol}//${req.nextUrl.host}`;
    const signInUrl = `${urlOrigin}/sign-in?redirect_url=${encodeURIComponent(pathname)}`;
    const redirectResponse = NextResponse.redirect(signInUrl);
    addCorsHeaders(redirectResponse, origin, host);
    return redirectResponse;
  }

  // Authenticated page - allow through
  const response = NextResponse.next({
    request: {
      headers: req.headers,
    },
  });
  addCorsHeaders(response, origin, host);
  return response;
});

export const config = {
  matcher: [
    '/api/(.*)',
  ],
};

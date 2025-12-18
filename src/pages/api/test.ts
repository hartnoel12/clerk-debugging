import { NextApiRequest, NextApiResponse } from 'next';
import { getAuth } from '@clerk/nextjs/server';

// Force Node.js runtime to ensure Clerk auth context is properly passed from Edge middleware
export const config = {
  runtime: 'nodejs',
};

/**
 * Test API endpoint to demonstrate authentication
 * Uses getAuth(req) which reads from the request object augmented by clerkMiddleware
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // Diagnostic logging
  const cookieHeader = req.headers.cookie || '';
  const hasSessionCookie = cookieHeader.includes('__session');
  
  console.log('[TEST-API] Request received', {
    method: req.method,
    url: req.url,
    hasSessionCookie,
    cookieHeaderLength: cookieHeader.length,
  });

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Use getAuth(req) to read from request object augmented by clerkMiddleware
    // getAuth(req) is synchronous (no await needed) for Pages Router
    let getAuthResult;
    try {
      console.log('[TEST-API] Calling getAuth(req)...');
      getAuthResult = getAuth(req);
      console.log('[TEST-API] getAuth(req) succeeded', {
        hasUserId: !!getAuthResult?.userId,
        userId: getAuthResult?.userId || null,
        hasSessionId: !!getAuthResult?.sessionId,
      });
    } catch (getAuthError) {
      const errorMessage = getAuthError instanceof Error ? getAuthError.message : 'unknown';
      console.error('[TEST-API] getAuth(req) threw error', {
        error: errorMessage,
        pathname: req.url,
      });
      throw getAuthError;
    }

    const { userId, sessionId } = getAuthResult;
    
    if (!userId) {
      console.log('[TEST-API] No userId from getAuth(req)', {
        hasSessionCookie,
      });
      return res.status(401).json({
        error: 'Authentication required',
        debug_hint: hasSessionCookie
          ? 'Cookie present but getAuth() returned null'
          : 'No session cookie found',
      });
    }

    console.log('[TEST-API] Success - returning user info', {
      userId,
      sessionId: sessionId || null,
    });

    return res.status(200).json({
      success: true,
      userId,
      sessionId: sessionId || null,
      message: 'Authentication working!',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('[TEST-API] Unexpected error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
    });
    return res.status(500).json({
      error: 'Internal server error',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}
import { NextApiRequest, NextApiResponse } from 'next';

import { logger } from '../../lib/utils/logger';
import { AuthorizationService } from '../../lib/auth/authorization';

const authService = new AuthorizationService();

// Force Node.js runtime to ensure Clerk auth context is properly passed from Edge middleware
export const config = {
  runtime: 'nodejs',
};

/**
 * Test API endpoint to demonstrate authentication
 * Uses AuthorizationService.getAuthenticatedUser() which uses getAuth(req) internally
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // Diagnostic logging
  const cookieHeader = req.headers.cookie || '';
  const hasSessionCookie = cookieHeader.includes('__session');

  logger.info('[TEST-API] Request received', {
    method: req.method,
    url: req.url,
    hasSessionCookie,
    cookieHeaderLength: cookieHeader.length,
  });

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Get authenticated user using AuthorizationService (same pattern as other API routes)
    let userId: string | null = null;
    try {
      logger.info('[TEST-API] Calling getAuthenticatedUser...');
      const user = await authService.getAuthenticatedUser(req, res);
      logger.info('[TEST-API] getAuthenticatedUser result', {
        hasUser: !!user,
        userId: user?.clerkId || null,
        internalUserId: user?.id || null,
      });

      userId = user?.clerkId || null;

      if (!userId) {
        logger.warn('[TEST-API] No userId from getAuthenticatedUser', {
          hasSessionCookie,
        });
        return res.status(401).json({
          error: 'Authentication required',
          debug_hint: hasSessionCookie
            ? 'Cookie present but getAuth() returned null'
            : 'No session cookie found',
        });
      }
    } catch (authError) {
      logger.error('[TEST-API] Error getting auth', {
        error: authError instanceof Error ? authError.message : 'Unknown error',
        hasSessionCookie,
        stack: authError instanceof Error ? authError.stack : undefined,
      });
      return res.status(401).json({
        error: 'Authentication required',
        debug_hint: authError instanceof Error ? authError.message : 'Unknown auth error',
      });
    }

    logger.info('[TEST-API] Success - returning user info', {
      userId,
    });

    return res.status(200).json({
      success: true,
      userId,
      message: 'Authentication working!',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('[TEST-API] Unexpected error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
    });
    return res.status(500).json({
      error: 'Internal server error',
      message: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}
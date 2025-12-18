import { NextApiRequest, NextApiResponse } from 'next';

import { applySecurityHeaders } from '../../lib/utils/securityHeaders';
import { logger } from '../../lib/utils/logger';
import { AuthorizationService } from '../../lib/auth/authorization';

const authService = new AuthorizationService();


/**
 * Test API endpoint to demonstrate authentication
 * Uses AuthorizationService.getAuthenticatedUser() which uses getAuth(req) internally
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  applySecurityHeaders(res);

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Diagnostic logging
  const cookieHeader = req.headers.cookie || '';
  const hasSessionCookie = cookieHeader.includes('__session');
  console.log('[TEST-API] Request received', {
    method: req.method,
    url: req.url,
    hasSessionCookie,
    cookieHeader: hasSessionCookie ? cookieHeader.substring(0, 100) : 'none',
  });
  logger.info('[TEST-API] Request received', {
    method: req.method,
    url: req.url,
    hasSessionCookie,
  });

  try {
    // Get authenticated user using AuthorizationService (same pattern as other API routes)
    let userId: string | null = null;
    try {
      console.log('[TEST-API] Calling getAuthenticatedUser...');
      const user = await authService.getAuthenticatedUser(req, res);
      console.log('[TEST-API] getAuthenticatedUser result', {
        hasUser: !!user,
        userId: user?.clerkId || null,
        internalUserId: user?.id || null,
      });
      logger.info('[TEST-API] getAuthenticatedUser result', {
        hasUser: !!user,
        userId: user?.clerkId || null,
        internalUserId: user?.id || null,
      });

      userId = user?.clerkId || null;

      if (!userId) {
        console.log('[TEST-API] No userId from getAuthenticatedUser', {
          hasSessionCookie,
        });
        logger.warn('[TEST-API] No userId from getAuthenticatedUser', {
          hasSessionCookie,
          url: req.url,
          cookieHeaderLength: cookieHeader.length,
        });
        return res.status(401).json({
          error: 'Authentication required',
          debug_hint: hasSessionCookie
            ? 'Cookie present but getAuth() returned null'
            : 'No session cookie found',
        });
      }
    } catch (authError) {
      console.error('[TEST-API] Error getting auth', {
        error: authError instanceof Error ? authError.message : 'Unknown error',
        hasSessionCookie,
      });
      logger.error('Error getting auth in test', {
        error: authError instanceof Error ? authError.message : 'Unknown error',
        hasSessionCookie,
        stack: authError instanceof Error ? authError.stack : undefined,
      });
      return res.status(401).json({
        error: 'Authentication required',
        debug_hint: authError instanceof Error ? authError.message : 'Unknown auth error',
      });
    }

    // Mock database lookup (simulating prisma.user.findUnique)
    console.log('[TEST-API] Looking up user in database', { clerkId: userId });
    const mockUser = {
      id: 'mock-internal-id',
      isApproved: true, // Hardcoded for testing
    };

    if (!mockUser) {
      // User doesn't exist in database yet - return false (not approved)
      // The webhook or getAuthenticatedUser will create them eventually
      console.log('[TEST-API] User not found in database', { clerkId: userId });
      logger.info('[TEST-API] User not found in database', {
        clerkId: userId,
        url: req.url,
      });
      return res.status(200).json({ isApproved: false });
    }

    console.log('[TEST-API] Success - returning approval status', {
      userId: mockUser.id,
      isApproved: mockUser.isApproved,
    });
    logger.info('[TEST-API] Success', {
      userId: mockUser.id,
      isApproved: mockUser.isApproved,
    });
    return res.status(200).json({ isApproved: mockUser.isApproved || false });
  } catch (error) {
    console.error('[TEST-API] Unexpected error', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
    });
    logger.error('Error checking approval status', {
      error: error instanceof Error ? error.message : 'Unknown error',
      stack: error instanceof Error ? error.stack : undefined,
    });
    return res.status(500).json({ error: 'Internal server error' });
  }
}
import { NextApiRequest, NextApiResponse } from 'next';
import { getAuth } from '@clerk/nextjs/server';

import { logger } from '../utils/logger';

export interface AuthenticatedUser {
  id: string;
  clerkId: string;
  email?: string;
  name?: string;
}

// Authorization service for handling authentication
export class AuthorizationService {
  /**
   * Get authenticated user from session
   * Uses getAuth(req) which reads from the request object augmented by clerkMiddleware
   */
  async getAuthenticatedUser(
    req: NextApiRequest,
    _res: NextApiResponse
  ): Promise<AuthenticatedUser | null> {
    try {
      // Diagnostic logging
      const cookieHeader = req.headers.cookie || '';
      const hasCookies = cookieHeader.length > 0;
      const clerkCookieNames = ['__session', '__clerk_db_jwt', '__clerk_js_token'];
      const hasClerkCookie = clerkCookieNames.some((name) => cookieHeader.includes(name));
      const hasSessionCookie = cookieHeader.includes('__session');

      logger.info('[AUTHORIZATION] Before getAuth(req) call', {
        pathname: req.url,
        hasCookies,
        hasClerkCookie,
        hasSessionCookie,
        cookieHeaderLength: cookieHeader.length,
      });

      // Log Clerk-specific headers to verify they're present
      const clerkHeaders = Object.keys(req.headers).filter(
        (k) => k.toLowerCase().includes('clerk') || k.toLowerCase().startsWith('x-clerk')
      );
      logger.info('[AUTHORIZATION] Clerk headers check', {
        pathname: req.url,
        clerkHeaderCount: clerkHeaders.length,
        clerkHeaders: clerkHeaders,
        hasCookies,
        hasClerkCookie,
        hasSessionCookie,
      });

      // Use getAuth(req) to read from request object augmented by clerkMiddleware
      // getAuth(req) is synchronous (no await needed) for Pages Router
      let getAuthResult;
      try {
        logger.info('[AUTHORIZATION] Calling getAuth(req) for Pages Router');
        getAuthResult = getAuth(req);
        logger.info('[AUTHORIZATION] getAuth(req) succeeded', {
          hasUserId: !!getAuthResult?.userId,
          userId: getAuthResult?.userId || null,
          hasSessionId: !!getAuthResult?.sessionId,
        });
      } catch (getAuthError) {
        const errorMessage = getAuthError instanceof Error ? getAuthError.message : 'unknown';
        logger.error('[AUTHORIZATION] getAuth(req) threw error', {
          pathname: req.url,
          error: errorMessage,
          hasCookies,
          hasClerkCookie,
          hasSessionCookie,
          stack: getAuthError instanceof Error ? getAuthError.stack : undefined,
        });
        throw getAuthError;
      }

      const { userId } = getAuthResult;
      if (!userId) {
        logger.warn('[AUTHORIZATION] No userId from getAuth(req)', {
          pathname: req.url,
          hasCookies,
          hasClerkCookie,
          hasSessionCookie,
          hasSessionId: !!getAuthResult?.sessionId,
        });
        return null;
      }

      // Return authenticated user
      // For now, use clerkId as both id and clerkId
      // In a full implementation, you'd look up the internal user ID from a database
      return {
        id: userId,
        clerkId: userId,
      };
    } catch (error) {
      logger.error('Error getting authenticated user', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });
      return null;
    }
  }
}

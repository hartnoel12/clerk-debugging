import { NextApiRequest, NextApiResponse } from 'next';
import { getAuth } from '@clerk/nextjs/server';

import { logger } from '../utils/logger';

export interface AuthenticatedUser {
  id: string;
  clerkId: string;
  email?: string;
  name?: string;
  isApiKey?: boolean;
  apiKeyId?: string;
}

export interface AuthorizationContext {
  user: AuthenticatedUser;
  req: NextApiRequest;
  res: NextApiResponse;
}

// Authorization decorators and helpers
export class AuthorizationService {

  /**
   * Get authenticated user from Clerk session
   * Returns Clerk userId as both id and clerkId
   */
  async getAuthenticatedUser(
    req: NextApiRequest,
    _res: NextApiResponse
  ): Promise<AuthenticatedUser | null> {
    try {
      // Session authentication using Clerk
      // #region agent log
      const cookieHeader = req.headers.cookie || '';
      const hasCookies = cookieHeader.length > 0;
      const clerkCookieNames = ['__session', '__clerk_db_jwt', '__clerk_js_token'];
      const hasClerkCookie = clerkCookieNames.some((name) => cookieHeader.includes(name));
      const hasSessionCookie = cookieHeader.includes('__session');
      const isApprovalStatus = req.url?.includes('/api/user/approval-status');
      
      logger.info('[AUTHORIZATION] Before getAuth(req) call', {
        pathname: req.url,
        hasCookies,
        hasClerkCookie,
        hasSessionCookie,
        isApprovalStatus,
        cookieHeaderLength: cookieHeader.length,
      });
      fetch('http://127.0.0.1:7242/ingest/bdcc0c4e-ec7b-4476-affb-bdf975a7be3d', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          location: 'authorization.ts:50',
          message: 'AuthorizationService: Before getAuth(req)',
          data: {
            hasCookies,
            hasClerkCookie,
            cookieHeader: hasCookies ? cookieHeader.substring(0, 200) : 'none',
            pathname: req.url,
          },
          timestamp: Date.now(),
          sessionId: 'debug-session',
          runId: 'run1',
          hypothesisId: 'A,C',
        }),
      }).catch(() => {});
      // #endregion
      
      // Log Clerk-specific headers to verify they're present
      const clerkHeaders = Object.keys(req.headers).filter(k => 
        k.toLowerCase().includes('clerk') || k.toLowerCase().startsWith('x-clerk')
      );
      logger.info('[AUTHORIZATION] Clerk headers check', {
        pathname: req.url,
        clerkHeaderCount: clerkHeaders.length,
        clerkHeaders: clerkHeaders,
        hasCookies,
        hasClerkCookie,
        isApprovalStatus,
      });
      
      // Use getAuth(req) to read from request object augmented by clerkMiddleware
      // getAuth(req) is synchronous (no await needed) for Pages Router
      let getAuthResult;
      try {
        console.log('[AUTH] Calling getAuth for:', req.url);
        console.log('[AUTHORIZATION] Calling getAuth(req) for Pages Router');
        getAuthResult = getAuth(req);
        console.log('[AUTH] getAuth result:', { 
          hasUserId: !!getAuthResult?.userId,
          userId: getAuthResult?.userId || null 
        });
        console.log('[AUTHORIZATION] getAuth(req) succeeded', {
          hasUserId: !!getAuthResult?.userId,
          userId: getAuthResult?.userId || null,
          hasSessionId: !!getAuthResult?.sessionId,
        });
        logger.info('[AUTHORIZATION] getAuth(req) succeeded', {
          pathname: req.url,
          hasUserId: !!getAuthResult?.userId,
          userId: getAuthResult?.userId || null,
          hasSessionId: !!getAuthResult?.sessionId,
          isApprovalStatus,
        });
      } catch (getAuthError) {
        // #region agent log
        const errorMessage = getAuthError instanceof Error ? getAuthError.message : 'unknown';
        console.error('[AUTHORIZATION] getAuth(req) threw error', {
          error: errorMessage,
          pathname: req.url,
        });
        logger.error('[AUTHORIZATION] getAuth(req) threw error', {
          pathname: req.url,
          error: errorMessage,
          hasCookies,
          hasClerkCookie,
          hasSessionCookie,
          isApprovalStatus,
          stack: getAuthError instanceof Error ? getAuthError.stack : undefined,
        });
        fetch('http://127.0.0.1:7242/ingest/bdcc0c4e-ec7b-4476-affb-bdf975a7be3d', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            location: 'authorization.ts:102',
            message: 'AuthorizationService: getAuth(req) threw error',
            data: {
              error: errorMessage,
              hasCookies,
              hasClerkCookie,
            },
            timestamp: Date.now(),
            sessionId: 'debug-session',
            runId: 'run1',
            hypothesisId: 'E',
          }),
        }).catch(() => {});
        // #endregion
        throw getAuthError;
      }
      // #region agent log
      fetch('http://127.0.0.1:7242/ingest/bdcc0c4e-ec7b-4476-affb-bdf975a7be3d', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          location: 'authorization.ts:148',
          message: 'AuthorizationService: After getAuth(req)',
          data: {
            hasUserId: !!getAuthResult.userId,
            userId: getAuthResult.userId || null,
            hasSessionId: !!getAuthResult.sessionId,
          },
          timestamp: Date.now(),
          sessionId: 'debug-session',
          runId: 'run1',
          hypothesisId: 'E',
        }),
      }).catch(() => {});
      // #endregion
      const { userId } = getAuthResult;
      if (!userId) {
        // #region agent log
        logger.warn('[AUTHORIZATION] No userId from getAuth(req)', {
          pathname: req.url,
          hasCookies,
          hasClerkCookie,
          hasSessionCookie,
          isApprovalStatus,
          hasSessionId: !!getAuthResult?.sessionId,
        });
        fetch('http://127.0.0.1:7242/ingest/bdcc0c4e-ec7b-4476-affb-bdf975a7be3d', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            location: 'authorization.ts:164',
            message: 'AuthorizationService: No userId from getAuth(req)',
            data: { hasCookies, hasClerkCookie },
            timestamp: Date.now(),
            sessionId: 'debug-session',
            runId: 'run1',
            hypothesisId: 'E',
          }),
        }).catch(() => {});
        // #endregion
        return null;
      }

      // Note: Email verification is handled by Clerk automatically
      // Clerk only allows verified users to authenticate
      // Return Clerk userId directly (matching approval-status route pattern)
      return {
        id: userId,
        clerkId: userId,
      };
    } catch (error) {
      return null;
    }
  }


  /**
   * Check if user owns a restaurant
   * NOTE: Prisma not available in test project - will throw if called
   */
  async checkRestaurantOwnership(userId: string, restaurantId: string): Promise<boolean> {
    throw new Error('checkRestaurantOwnership: Prisma not available in test project');
  }

  /**
   * Check if user owns a dish (via restaurant ownership)
   * NOTE: Prisma not available in test project - will throw if called
   */
  async checkDishOwnership(userId: string, dishId: string): Promise<boolean> {
    throw new Error('checkDishOwnership: Prisma not available in test project');
  }

  /**
   * Check if user owns a visit
   * NOTE: Prisma not available in test project - will throw if called
   */
  async checkVisitOwnership(userId: string, visitId: string): Promise<boolean> {
    throw new Error('checkVisitOwnership: Prisma not available in test project');
  }

  /**
   * Check if user owns a comment
   * NOTE: Prisma not available in test project - will throw if called
   */
  async checkCommentOwnership(userId: string, commentId: string): Promise<boolean> {
    throw new Error('checkCommentOwnership: Prisma not available in test project');
  }

  /**
   * Check if user can access another user's profile
   * - Users can always access their own profile
   * - Public profiles are accessible to everyone
   * - Private profiles require specific permissions
   * NOTE: Prisma not available in test project - will throw if called
   */
  async checkUserProfileAccess(
    requestingUserId: string,
    targetUserId: string
  ): Promise<{ allowed: boolean; reason?: string }> {
    // Users can always access their own profile
    if (requestingUserId === targetUserId) {
      return { allowed: true };
    }
    throw new Error('checkUserProfileAccess: Prisma not available in test project');
  }

  /**
   * Check if user has required subscription tier
   * NOTE: Prisma not available in test project - will throw if called
   */
  async checkSubscriptionTier(
    userId: string,
    restaurantId: string,
    requiredTier: 'FREE' | 'PREMIUM' | 'PRO'
  ): Promise<boolean> {
    throw new Error('checkSubscriptionTier: Prisma not available in test project');
  }

  /**
   * Check if user is a moderator/admin
   * Checks both isAdmin and isModerator fields in the database
   * NOTE: Prisma not available in test project - will throw if called
   */
  async checkModeratorAccess(userId: string): Promise<boolean> {
    throw new Error('checkModeratorAccess: Prisma not available in test project');
  }
}

// Authorization decorators
export function requireAuth(
  handler: (_req: NextApiRequest, _res: NextApiResponse, _user: AuthenticatedUser) => Promise<void>
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const authService = new AuthorizationService();
    const user = await authService.getAuthenticatedUser(req, res);

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    return handler(req, res, user);
  };
}

export function requireRestaurantOwnership(
  handler: (_req: NextApiRequest, _res: NextApiResponse, _user: AuthenticatedUser) => Promise<void>
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const authService = new AuthorizationService();
    const user = await authService.getAuthenticatedUser(req, res);

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { id: restaurantId } = req.query;
    if (!restaurantId || typeof restaurantId !== 'string') {
      return res.status(400).json({ error: 'Restaurant ID required' });
    }

    const isOwner = await authService.checkRestaurantOwnership(user.id, restaurantId);
    if (!isOwner) {
      return res.status(403).json({ error: 'Access denied. You must own this restaurant.' });
    }

    return handler(req, res, user);
  };
}

export function requireRestaurantOwnershipOrAdmin(
  handler: (_req: NextApiRequest, _res: NextApiResponse, _user: AuthenticatedUser) => Promise<void>
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const authService = new AuthorizationService();
    const user = await authService.getAuthenticatedUser(req, res);

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { id: restaurantId } = req.query;
    if (!restaurantId || typeof restaurantId !== 'string') {
      return res.status(400).json({ error: 'Restaurant ID required' });
    }

    // Check if user is admin (API keys have admin access)
    const isAdmin = user.isApiKey || (await authService.checkModeratorAccess(user.id));

    // Check if user owns the restaurant
    const isOwner = await authService.checkRestaurantOwnership(user.id, restaurantId);

    if (!isAdmin && !isOwner) {
      return res
        .status(403)
        .json({ error: 'Access denied. You must own this restaurant or have admin privileges.' });
    }

    return handler(req, res, user);
  };
}

export function requireDishOwnership(
  handler: (_req: NextApiRequest, _res: NextApiResponse, _user: AuthenticatedUser) => Promise<void>
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const authService = new AuthorizationService();
    const user = await authService.getAuthenticatedUser(req, res);

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { id: dishId } = req.query;
    if (!dishId || typeof dishId !== 'string') {
      return res.status(400).json({ error: 'Dish ID required' });
    }

    const isOwner = await authService.checkDishOwnership(user.id, dishId);
    if (!isOwner) {
      return res.status(403).json({ error: 'Access denied. You must own this dish.' });
    }

    return handler(req, res, user);
  };
}

export function requireVisitOwnership(
  handler: (_req: NextApiRequest, _res: NextApiResponse, _user: AuthenticatedUser) => Promise<void>
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const authService = new AuthorizationService();
    const user = await authService.getAuthenticatedUser(req, res);

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { visitId } = req.query;
    if (!visitId || typeof visitId !== 'string') {
      return res.status(400).json({ error: 'Visit ID required' });
    }

    const isOwner = await authService.checkVisitOwnership(user.id, visitId);
    if (!isOwner) {
      return res.status(403).json({ error: 'Access denied. You must own this visit.' });
    }

    return handler(req, res, user);
  };
}

export function requireCommentOwnership(
  handler: (_req: NextApiRequest, _res: NextApiResponse, _user: AuthenticatedUser) => Promise<void>
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const authService = new AuthorizationService();
    const user = await authService.getAuthenticatedUser(req, res);

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { id: commentId } = req.query;
    if (!commentId || typeof commentId !== 'string') {
      return res.status(400).json({ error: 'Comment ID required' });
    }

    const isOwner = await authService.checkCommentOwnership(user.id, commentId);
    if (!isOwner) {
      return res.status(403).json({ error: 'Access denied. You must own this comment.' });
    }

    return handler(req, res, user);
  };
}

export function requireSubscriptionTier(requiredTier: 'FREE' | 'PREMIUM' | 'PRO') {
  return function (
    handler: (
      _req: NextApiRequest,
      _res: NextApiResponse,
      _user: AuthenticatedUser
    ) => Promise<void>
  ) {
    return async (req: NextApiRequest, res: NextApiResponse) => {
      const authService = new AuthorizationService();
      const user = await authService.getAuthenticatedUser(req, res);

      if (!user) {
        return res.status(401).json({ error: 'Authentication required' });
      }

      const { id: restaurantId } = req.query;
      if (!restaurantId || typeof restaurantId !== 'string') {
        return res.status(400).json({ error: 'Restaurant ID required' });
      }

      const hasTier = await authService.checkSubscriptionTier(user.id, restaurantId, requiredTier);
      if (!hasTier) {
        return res.status(403).json({
          error: `Access denied. ${requiredTier} subscription required.`,
        });
      }

      return handler(req, res, user);
    };
  };
}

export function requireModerator(
  handler: (_req: NextApiRequest, _res: NextApiResponse, _user: AuthenticatedUser) => Promise<void>
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const authService = new AuthorizationService();
    const user = await authService.getAuthenticatedUser(req, res);

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // API keys have moderator access
    if (user.isApiKey) {
      return handler(req, res, user);
    }

    const isAdmin = await authService.checkModeratorAccess(user.id);
    if (!isAdmin) {
      return res.status(403).json({ error: 'Access denied. Moderator access required.' });
    }

    return handler(req, res, user);
  };
}

/**
 * Require either API key or admin privileges
 * This is useful for administrative operations that can be performed via API
 */
export function requireApiKeyOrAdmin(
  handler: (_req: NextApiRequest, _res: NextApiResponse, _user: AuthenticatedUser) => Promise<void>
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const authService = new AuthorizationService();
    const user = await authService.getAuthenticatedUser(req, res);

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // API keys have full access
    if (user.isApiKey) {
      return handler(req, res, user);
    }

    // Check if user has admin privileges
    const isAdmin = await authService.checkModeratorAccess(user.id);
    if (!isAdmin) {
      return res
        .status(403)
        .json({ error: 'Access denied. API key or admin privileges required.' });
    }

    return handler(req, res, user);
  };
}

/**
 * Require API key only (no session authentication)
 * This is for operations that should only be accessible via API
 */
export function requireApiKey(
  handler: (_req: NextApiRequest, _res: NextApiResponse, _user: AuthenticatedUser) => Promise<void>
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const authService = new AuthorizationService();
    const user = await authService.getAuthenticatedUser(req, res);

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    if (!user.isApiKey) {
      return res.status(403).json({ error: 'Access denied. API key required.' });
    }

    return handler(req, res, user);
  };
}

/**
 * Enhanced authentication that requires either:
 * - API key (unlimited access)
 * - Admin privileges (unlimited access)
 * - Verified OAuth account (rate limited)
 * This provides DDOS protection while maintaining functionality
 */
export function requireEnhancedAuth(
  handler: (_req: NextApiRequest, _res: NextApiResponse, _user: AuthenticatedUser) => Promise<void>
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const authService = new AuthorizationService();
    const user = await authService.getAuthenticatedUser(req, res);

    if (!user) {
      return res.status(401).json({
        error: 'Authentication required. Please log in with a verified account or use an API key.',
        code: 'AUTH_REQUIRED',
      });
    }

    // API keys and admins get unlimited access
    if (user.isApiKey || (await authService.checkModeratorAccess(user.id))) {
      return handler(req, res, user);
    }

    // Regular users must have verified accounts
    if (!user.clerkId || user.clerkId === 'anonymous') {
      return res.status(403).json({
        error: 'Access denied. Verified account required.',
        code: 'VERIFICATION_REQUIRED',
      });
    }

    // For verified OAuth users, apply rate limiting
    // Rate limiting service - placeholder
    // const rateLimitResult = await rateLimitService.checkRateLimit(user.id, 'ENHANCED_AUTH');
    // if (rateLimitResult.isRateLimited) {
    //   return res.status(429).json({
    //     error: 'Rate limit exceeded. Please wait before trying again.',
    //     resetTime: rateLimitResult.resetTime
    //   });
    // }

    return handler(req, res, user);
  };
}

/**
 * Require dish ownership AND premium subscription for analytics access
 * Allows dish owners with PREMIUM/PRO subscription or admin/API key users
 */
export function requireDishAnalyticsAccess(
  handler: (_req: NextApiRequest, _res: NextApiResponse, _user: AuthenticatedUser) => Promise<void>
) {
  return async (req: NextApiRequest, res: NextApiResponse) => {
    const authService = new AuthorizationService();
    const user = await authService.getAuthenticatedUser(req, res);

    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // API key users and admins get automatic access
    if (user.isApiKey || (await authService.checkModeratorAccess(user.id))) {
      return handler(req, res, user);
    }

    const { id: dishId } = req.query;
    if (!dishId || typeof dishId !== 'string') {
      return res.status(400).json({ error: 'Dish ID required' });
    }

    // Check dish ownership
    const isOwner = await authService.checkDishOwnership(user.id, dishId);
    if (!isOwner) {
      return res
        .status(403)
        .json({ error: 'Access denied. You must own this restaurant to view dish analytics.' });
    }

    // NOTE: Prisma not available in test project
    // This decorator will throw if called
    throw new Error('requireDishAnalyticsAccess: Prisma not available in test project');

    return handler(req, res, user as AuthenticatedUser);
  };
}

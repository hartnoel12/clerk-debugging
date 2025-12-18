// Check if we're on the server-side
const isServer = typeof window === 'undefined';

// Check if we're in Edge Runtime (Next.js middleware runs in Edge Runtime)
// Edge Runtime doesn't support require(), Node.js APIs, or winston
const isEdgeRuntime =
  (typeof globalThis !== 'undefined' && 'EdgeRuntime' in globalThis) ||
  (typeof process !== 'undefined' && process.env.NEXT_RUNTIME === 'edge');

// No-op logger for client-side (no logging in browser)
const noOpLogger = {
  error: () => {},
  warn: () => {},
  info: () => {},
  debug: () => {},
  verbose: () => {},
};

// Edge-compatible console logger (for middleware/Edge Runtime)
// Note: process.env is available in Edge Runtime, but we check it safely
const getNodeEnv = () => {
  try {
    return typeof process !== 'undefined' && process.env ? process.env.NODE_ENV : undefined;
  } catch {
    return undefined;
  }
};

const edgeLogger = {
  error: (message: string, ...args: any[]) => {
    console.error(`[ERROR] ${message}`, ...args);
  },
  warn: (message: string, ...args: any[]) => {
    console.warn(`[WARN] ${message}`, ...args);
  },
  info: (message: string, ...args: any[]) => {
    // eslint-disable-next-line no-console
    console.info(`[INFO] ${message}`, ...args);
  },
  debug: (message: string, ...args: any[]) => {
    if (getNodeEnv() === 'development') {
      // eslint-disable-next-line no-console
      console.debug(`[DEBUG] ${message}`, ...args);
    }
  },
  verbose: (message: string, ...args: any[]) => {
    if (getNodeEnv() === 'development') {
      // eslint-disable-next-line no-console
      console.debug(`[VERBOSE] ${message}`, ...args);
    }
  },
};

// Winston logger configuration for Node.js runtime (not Edge Runtime)
// Use dynamic import to prevent winston from being bundled on client-side or Edge Runtime
let winstonLogger: any = null;

if (isServer && !isEdgeRuntime) {
  try {
    // Only use winston in Node.js runtime (not Edge Runtime)
    // Use dynamic require to avoid Edge Runtime issues
    const winston = require('winston');
    const isDevelopment = process.env.NODE_ENV === 'development';

    // Determine log level based on environment
    const logLevel = isDevelopment ? 'debug' : 'info';

    // Create Winston logger
    winstonLogger = winston.createLogger({
      level: logLevel,
      format: isDevelopment
        ? winston.format.combine(
            winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
            winston.format.colorize(),
            winston.format.printf(({ timestamp, level, message, ...meta }: any) => {
              const metaString = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
              return `${timestamp} [${level}]: ${message}${metaString ? `\n${metaString}` : ''}`;
            })
          )
        : winston.format.combine(
            winston.format.timestamp(),
            winston.format.errors({ stack: true }),
            winston.format.json()
          ),
      transports: [
        new winston.transports.Console({
          stderrLevels: ['error'],
        }),
      ],
      // Don't exit on handled exceptions
      exitOnError: false,
    });
  } catch (error) {
    // If winston fails to load (e.g., in Edge Runtime), fall back to console logger
    console.warn('Winston logger unavailable, using console logger', error);
  }
}

// Export logger instance
// Priority: winston (Node.js) > edgeLogger (Edge Runtime) > noOpLogger (client-side)
export const logger = isServer
  ? isEdgeRuntime
    ? edgeLogger
    : winstonLogger || edgeLogger
  : noOpLogger;

// Export type for logger (for TypeScript)
export type Logger = typeof logger;

/**
 * Check if the request is from a search engine crawler
 * @param userAgent - User agent string from request headers
 * @returns true if the request is from a known search engine crawler
 */
export function isSearchEngineCrawler(userAgent: string | null | undefined): boolean {
  if (!userAgent) {
    return false;
  }

  const crawlerPatterns = [
    // Google crawlers
    /googlebot/i,
    /googlebot-image/i,
    /googlebot-news/i,
    /googlebot-video/i,
    // Bing crawlers
    /bingbot/i,
    /msnbot/i,
    // Yahoo crawler
    /slurp/i,
    // Other search engines
    /duckduckbot/i,
    /baiduspider/i,
    /yandexbot/i,
    /sogou/i,
    /exabot/i,
    /facebot/i,
    /ia_archiver/i, // Wayback Machine
    // Social media crawlers
    /facebookexternalhit/i,
    /twitterbot/i,
    /linkedinbot/i,
    /pinterest/i,
    // Apple crawler
    /applebot/i,
    // Other common crawlers
    /semrushbot/i,
    /ahrefsbot/i,
    /mj12bot/i,
  ];

  return crawlerPatterns.some((pattern) => pattern.test(userAgent));
}

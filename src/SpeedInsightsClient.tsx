'use client';

import dynamic from 'next/dynamic';
import { useEffect, useState } from 'react';

const SpeedInsightsNoSSR = dynamic(
  () => import('@vercel/speed-insights/next').then((m) => m.SpeedInsights),
  { ssr: false }
);

export default function SpeedInsightsClient(props: any) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return null;
  }

  return <SpeedInsightsNoSSR {...props} />;
}

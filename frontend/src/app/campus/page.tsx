import type { Metadata } from 'next';
import { createMetadata } from '@/lib/seo';

export const dynamic = 'force-dynamic';

import nextDynamic from 'next/dynamic';
import ErrorBoundary from '../../components/ErrorBoundary';

const MetaverseCampus = nextDynamic(
  () => import('../../components/Metaverse').then((mod) => mod.MetaverseCampus),
  {
    loading: () => (
      <div className="flex items-center justify-center min-h-[600px] bg-slate-950 text-white">
        <div className="flex flex-col items-center gap-3">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-500"></div>
          <p className="text-sm text-slate-400">Loading Metaverse Campus 3D engine...</p>
        </div>
      </div>
    ),
    ssr: false,
  }
);

export const metadata: Metadata = {
  title: 'Metaverse Campus — StarkEd',
  description: 'Immersive virtual learning campus with classrooms, social spaces, and avatar interaction.',
  keywords: ['virtual campus', 'collaborative learning', 'online classroom'],
};

export default function CampusPage() {
  return (
    <ErrorBoundary>
      <MetaverseCampus />
    </ErrorBoundary>
  );
}

import type { Metadata } from 'next';
import { createMetadata } from '@/lib/seo';

export const dynamic = 'force-dynamic';

import nextDynamic from 'next/dynamic';
import ErrorBoundary from '../../components/ErrorBoundary';

const VirtualScienceLab = nextDynamic(
  () => import('../../components/Lab').then((mod) => mod.VirtualScienceLab),
  {
    loading: () => (
      <div className="flex items-center justify-center min-h-[600px] bg-gray-900 text-white">
        <div className="flex flex-col items-center gap-3">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
          <p className="text-sm text-gray-400">Loading Virtual Science Lab module...</p>
        </div>
      </div>
    ),
    ssr: false,
  }
);

export const metadata: Metadata = {
  title: 'Virtual Science Laboratory — StarkEd',
  description: 'Interactive virtual lab for experiments with 3D equipment, guided steps, safety warnings, and collaboration.',
};

export default function LabPage() {
  return (
    <ErrorBoundary>
      <VirtualScienceLab />
    </ErrorBoundary>
  );
}

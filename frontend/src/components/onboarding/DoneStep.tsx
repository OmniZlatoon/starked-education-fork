'use client';

import React, { useEffect } from 'react';
import Link from 'next/link';
import { PartyPopper, BookOpen, Settings, CheckCircle2 } from 'lucide-react';

export interface DoneStepProps {
  displayName: string;
  walletConnected: boolean;
  interestsCount: number;
  onComplete: () => void;
}

/**
 * DoneStep — final step of the onboarding wizard.
 *
 * Shows a celebration animation (confetti burst via CSS) and a summary of
 * what the user configured. The primary CTA navigates to the course catalog.
 * A secondary link goes to Settings for further customization.
 */
export const DoneStep: React.FC<DoneStepProps> = ({
  displayName,
  walletConnected,
  interestsCount,
  onComplete,
}) => {
  useEffect(() => {
    // Call onComplete after the celebration renders so the
    // `onboardingComplete` flag is persisted.
    onComplete();
  }, [onComplete]);

  const firstName = displayName.split(' ')[0] || displayName;

  return (
    <div className="flex flex-col items-center text-center py-6 px-4 sm:px-8">
      {/* Celebration animation — CSS-only confetti burst */}
      <div className="relative w-24 h-24 mb-6">
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-20 h-20 rounded-full bg-gradient-to-br from-green-400 to-blue-600 flex items-center justify-center shadow-xl animate-bounce">
            <PartyPopper className="w-10 h-10 text-white" aria-hidden="true" />
          </div>
        </div>
        {/* Confetti dots */}
        {[...Array(8)].map((_, i) => (
          <div
            key={i}
            className="absolute w-2 h-2 rounded-full"
            style={{
              top: '50%',
              left: '50%',
              backgroundColor: [
                '#fbbf24',
                '#f87171',
                '#60a5fa',
                '#34d399',
                '#a78bfa',
                '#fb7185',
                '#facc15',
                '#22d3ee',
              ][i],
              animation: `confetti-${i} 1s ease-out forwards`,
            }}
            aria-hidden="true"
          />
        ))}
      </div>

      <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white mb-2">
        You're All Set, {firstName}! 🎉
      </h1>
      <p className="text-base text-gray-600 dark:text-slate-300 max-w-md mb-8">
        Your profile is ready. Explore courses, earn verifiable credentials,
        and start your learning journey today.
      </p>

      {/* Setup summary */}
      <div className="w-full max-w-sm space-y-2 mb-8 text-left">
        <SummaryRow
          icon={CheckCircle2}
          label="Profile created"
          value={displayName}
          done
        />
        <SummaryRow
          icon={CheckCircle2}
          label="Wallet"
          value={walletConnected ? 'Connected' : 'Skipped (connect later in Settings)'}
          done={walletConnected}
        />
        <SummaryRow
          icon={CheckCircle2}
          label="Interests selected"
          value={interestsCount > 0 ? `${interestsCount} topics` : 'None yet'}
          done={interestsCount > 0}
        />
      </div>

      {/* CTAs */}
      <div className="flex flex-col sm:flex-row items-center gap-3 w-full max-w-sm">
        <Link
          href="/courses"
          className="flex items-center justify-center gap-2 w-full px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition-colors shadow-md hover:shadow-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 focus-visible:ring-offset-2"
        >
          <BookOpen className="w-5 h-5" aria-hidden="true" />
          Explore Courses
        </Link>
        <Link
          href="/settings"
          className="flex items-center justify-center gap-2 w-full px-6 py-3 bg-gray-100 dark:bg-slate-800 hover:bg-gray-200 dark:hover:bg-slate-700 text-gray-700 dark:text-slate-200 font-semibold rounded-xl transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-gray-400 focus-visible:ring-offset-2"
        >
          <Settings className="w-5 h-5" aria-hidden="true" />
          Go to Settings
        </Link>
      </div>

      {/* Confetti keyframes injected locally so they're always available */}
      <style jsx>{`
        @keyframes confetti-0 {
          to { transform: translate(-40px, -50px) scale(0); opacity: 0; }
        }
        @keyframes confetti-1 {
          to { transform: translate(40px, -50px) scale(0); opacity: 0; }
        }
        @keyframes confetti-2 {
          to { transform: translate(-50px, 20px) scale(0); opacity: 0; }
        }
        @keyframes confetti-3 {
          to { transform: translate(50px, 20px) scale(0); opacity: 0; }
        }
        @keyframes confetti-4 {
          to { transform: translate(-30px, -30px) scale(0); opacity: 0; }
        }
        @keyframes confetti-5 {
          to { transform: translate(30px, -30px) scale(0); opacity: 0; }
        }
        @keyframes confetti-6 {
          to { transform: translate(0, -60px) scale(0); opacity: 0; }
        }
        @keyframes confetti-7 {
          to { transform: translate(0, 60px) scale(0); opacity: 0; }
        }
      `}</style>
    </div>
  );
};

// ─── Helper sub-component ─────────────────────────────────────────────────

const SummaryRow: React.FC<{
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  done: boolean;
}> = ({ icon: Icon, label, value, done }) => (
  <div className="flex items-center gap-3 px-4 py-2.5 rounded-lg bg-gray-50 dark:bg-slate-800/50 border border-gray-100 dark:border-slate-700">
    <Icon
      className={
        done
          ? 'w-5 h-5 text-green-600 dark:text-green-400 flex-shrink-0'
          : 'w-5 h-5 text-gray-300 dark:text-slate-600 flex-shrink-0'
      }
      aria-hidden="true"
    />
    <div className="flex-1 min-w-0">
      <p className="text-xs text-gray-400 dark:text-slate-500">{label}</p>
      <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
        {value}
      </p>
    </div>
  </div>
);

export default DoneStep;

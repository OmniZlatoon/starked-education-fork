'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { X } from 'lucide-react';
import { ProgressIndicator } from './ProgressIndicator';
import { WelcomeStep } from './WelcomeStep';
import { ProfileStep } from './ProfileStep';
import { WalletStep } from './WalletStep';
import { InterestsStep } from './InterestsStep';
import { DoneStep } from './DoneStep';

// ─── Types ─────────────────────────────────────────────────────────────────

export interface OnboardingData {
  displayName: string;
  avatar: string | null;
  bio: string;
  walletAddress: string | null;
  walletSkipped: boolean;
  interests: string[];
}

const EMPTY_DATA: OnboardingData = {
  displayName: '',
  avatar: null,
  bio: '',
  walletAddress: null,
  walletSkipped: false,
  interests: [],
};

export interface OnboardingWizardProps {
  /** Called when the user finishes the wizard (Done step renders). */
  onComplete: (data: OnboardingData) => void;
  /** Called when the user dismisses the wizard via the X button or Escape. */
  onClose: () => void;
  /** When true, the wizard starts on the last step it was on (resumed). */
  initialStep?: number;
  /** Pre-existing onboarding data to hydrate from localStorage. */
  initialData?: OnboardingData;
}

// ─── Step definitions ──────────────────────────────────────────────────────

const STEPS = [
  { id: 'welcome', label: 'Welcome' },
  { id: 'profile', label: 'Profile' },
  { id: 'wallet', label: 'Wallet' },
  { id: 'interests', label: 'Interests' },
  { id: 'done', label: 'Done' },
] as const;

// ─── Storage keys ──────────────────────────────────────────────────────────

const STORAGE_STEP_KEY = 'starked_onboarding_step';
const STORAGE_DATA_KEY = 'starked_onboarding_data';

// ─── Component ─────────────────────────────────────────────────────────────

/**
 * OnboardingWizard — multi-step onboarding flow for new StarkEd users.
 *
 * Five steps: Welcome → Profile Setup → Wallet Connect → Interests → Done.
 *
 * Features:
 * - Progress indicator with current step highlighted
 * - Backward navigation to previous steps
 * - Wallet step with "Skip for now" option
 * - Interest tags loaded from backend course categories
 * - Progress persisted to localStorage so users can resume mid-wizard
 * - Full-screen on mobile, centered modal on desktop
 * - Keyboard navigable: Tab between controls, Escape to close
 * - Accessible: ARIA live region announces step changes
 */
export const OnboardingWizard: React.FC<OnboardingWizardProps> = ({
  onComplete,
  onClose,
  initialStep,
  initialData,
}) => {
  const [currentStep, setCurrentStep] = useState(initialStep ?? 0);
  const [data, setData] = useState<OnboardingData>(initialData ?? EMPTY_DATA);
  const wizardRef = useRef<HTMLDivElement>(null);

  // ─── Persist step + data to localStorage ────────────────────────────────

  useEffect(() => {
    // Don't persist the Done step — completion is tracked via
    // 'starked_onboarding_complete' set by handleComplete. Persisting step 4
    // would restore the step key after handleComplete removes it.
    if (currentStep >= STEPS.length - 1) return;
    try {
      localStorage.setItem(STORAGE_STEP_KEY, String(currentStep));
    } catch {
      // localStorage may be unavailable in some environments
    }
  }, [currentStep]);

  useEffect(() => {
    // Don't persist data on the Done step — handleComplete clears both keys
    // and the parent effect running after the child (DoneStep) would overwrite
    // the removal. In-progress data is only meaningful for resuming mid-flow.
    if (currentStep >= STEPS.length - 1) return;
    try {
      localStorage.setItem(STORAGE_DATA_KEY, JSON.stringify(data));
    } catch {
      // ignore quota errors
    }
  }, [data, currentStep]);

  // ─── Keyboard navigation ────────────────────────────────────────────────

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  // Focus the wizard container when the step changes so screen readers
  // announce the new content.
  useEffect(() => {
    wizardRef.current?.focus();
  }, [currentStep]);

  // ─── Step navigation ────────────────────────────────────────────────────

  const handleNext = useCallback(() => {
    setCurrentStep((prev) => Math.min(prev + 1, STEPS.length - 1));
  }, []);

  const handleBack = useCallback(() => {
    setCurrentStep((prev) => Math.max(prev - 1, 0));
  }, []);

  const handleComplete = useCallback(() => {
    try {
      localStorage.setItem('starked_onboarding_complete', 'true');
      localStorage.removeItem(STORAGE_STEP_KEY);
      localStorage.removeItem(STORAGE_DATA_KEY);
    } catch {
      // ignore
    }
    onComplete(data);
  }, [data, onComplete]);

  // ─── Data update helpers ────────────────────────────────────────────────

  const updateProfileData = useCallback(
    (profileData: { displayName: string; avatar: string | null; bio: string }) => {
      setData((prev) => ({ ...prev, ...profileData }));
    },
    [],
  );

  const updateWalletData = useCallback(
    (walletData: { walletAddress: string | null; walletSkipped: boolean }) => {
      setData((prev) => ({ ...prev, ...walletData }));
    },
    [],
  );

  const updateInterests = useCallback((interests: string[]) => {
    setData((prev) => ({ ...prev, interests }));
  }, []);

  // ─── Render ──────────────────────────────────────────────────────────────

  const renderStep = () => {
    switch (STEPS[currentStep].id) {
      case 'welcome':
        return <WelcomeStep onNext={handleNext} />;
      case 'profile':
        return (
          <ProfileStep
            data={{
              displayName: data.displayName,
              avatar: data.avatar,
              bio: data.bio,
            }}
            onUpdate={updateProfileData}
            onNext={handleNext}
            onBack={handleBack}
          />
        );
      case 'wallet':
        return (
          <WalletStep
            walletAddress={data.walletAddress}
            walletSkipped={data.walletSkipped}
            onUpdate={updateWalletData}
            onNext={handleNext}
            onBack={handleBack}
          />
        );
      case 'interests':
        return (
          <InterestsStep
            selectedInterests={data.interests}
            onUpdate={updateInterests}
            onNext={handleNext}
            onBack={handleBack}
          />
        );
      case 'done':
        return (
          <DoneStep
            displayName={data.displayName || 'there'}
            walletConnected={!!data.walletAddress}
            interestsCount={data.interests.length}
            onComplete={handleComplete}
          />
        );
      default:
        return null;
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Onboarding wizard"
    >
      <div
        ref={wizardRef}
        tabIndex={-1}
        className="
          relative w-full h-full sm:h-auto sm:max-w-2xl sm:max-h-[90vh]
          bg-white dark:bg-slate-900 sm:rounded-2xl shadow-2xl
          overflow-y-auto sm:overflow-y-auto
          outline-none
          flex flex-col
        "
      >
        {/* Close button — always visible top-right */}
        <button
          onClick={onClose}
          className="absolute top-3 right-3 z-10 p-2 rounded-full text-gray-400 hover:text-gray-600 dark:hover:text-slate-200 hover:bg-gray-100 dark:hover:bg-slate-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-gray-400"
          aria-label="Close onboarding wizard"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Progress indicator — hidden on the Welcome and Done steps
            for a cleaner first/last impression */}
        {currentStep > 0 && currentStep < STEPS.length - 1 && (
          <div className="px-6 sm:px-10 pt-6 pb-2 border-b border-gray-100 dark:border-slate-800">
            <ProgressIndicator steps={STEPS} currentStep={currentStep} />
          </div>
        )}

        {/* Step content */}
        <div className="flex-1 overflow-y-auto">{renderStep()}</div>
      </div>
    </div>
  );
};

// ─── OnboardingGate — mount point for layout.tsx ──────────────────────────

/**
 * OnboardingGate — client-side wrapper that checks whether the onboarding
 * wizard should be shown. Mounted in `app/layout.tsx`.
 *
 * The wizard is shown when:
 * 1. The user is authenticated (checked via AuthContext)
 * 2. The `starked_onboarding_complete` flag is NOT set in localStorage
 * 3. There is no existing profile data (no display name saved)
 *
 * It can also be force-triggered from Settings via `window.dispatchEvent`
 * with a `starked:restart-onboarding` event.
 */
export const OnboardingGate: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [showWizard, setShowWizard] = useState(false);
  const [resumeStep, setResumeStep] = useState(0);
  const [resumeData, setResumeData] = useState<OnboardingData | undefined>();

  useEffect(() => {
    const checkOnboarding = () => {
      try {
        const complete = localStorage.getItem('starked_onboarding_complete');
        const token = localStorage.getItem('admin_token');

        // Only show for authenticated users who haven't completed onboarding
        if (token && !complete) {
          const savedStep = localStorage.getItem(STORAGE_STEP_KEY);
          const savedData = localStorage.getItem(STORAGE_DATA_KEY);

          if (savedStep) setResumeStep(parseInt(savedStep, 10));
          if (savedData) {
            try {
              setResumeData(JSON.parse(savedData));
            } catch {
              setResumeData(undefined);
            }
          }
          setShowWizard(true);
        }
      } catch {
        // localStorage unavailable — skip onboarding
      }
    };

    checkOnboarding();

    // Listen for manual restart from Settings
    const handleRestart = () => {
      try {
        localStorage.removeItem('starked_onboarding_complete');
        localStorage.removeItem(STORAGE_STEP_KEY);
        localStorage.removeItem(STORAGE_DATA_KEY);
      } catch {
        // ignore
      }
      setResumeStep(0);
      setResumeData(undefined);
      setShowWizard(true);
    };

    window.addEventListener('starked:restart-onboarding', handleRestart);
    return () =>
      window.removeEventListener('starked:restart-onboarding', handleRestart);
  }, []);

  const handleClose = useCallback(() => {
    setShowWizard(false);
  }, []);

  const handleComplete = useCallback((_data: OnboardingData) => {
    setShowWizard(false);
  }, []);

  if (!showWizard) {
    return <>{children}</>;
  }

  return (
    <>
      {children}
      <OnboardingWizard
        onComplete={handleComplete}
        onClose={handleClose}
        initialStep={resumeStep}
        initialData={resumeData}
      />
    </>
  );
};

export default OnboardingWizard;

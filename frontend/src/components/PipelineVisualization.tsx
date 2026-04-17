import { useEffect, useRef, useState } from 'react';

interface Stage {
  stage: number;
  status: 'waiting' | 'active' | 'complete';
  label: string;
  detail: string;
}

interface PipelineVisualizationProps {
  iocType: string;
  iocValue: string;
  context: string;
  onComplete: (results: Record<string, unknown>) => void;
}

const STAGE_DEFS = [
  { label: 'IOC Ingestion & Enrichment', icon: '🔍' },
  { label: 'MITRE ATT&CK Mapping', icon: '🧠' },
  { label: 'RAG Validation', icon: '✅' },
  { label: 'Detection Rule Generation', icon: '📋' },
  { label: 'APT Projection & Proactive Rules', icon: '🎯' },
];

export default function PipelineVisualization({
  iocType,
  iocValue,
  context,
  onComplete,
}: PipelineVisualizationProps) {
  const [stages, setStages] = useState<Stage[]>(
    STAGE_DEFS.map((s, i) => ({
      stage: i,
      status: 'waiting',
      label: s.label,
      detail: '',
    }))
  );

  const [pipelineError, setPipelineError] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    runPipeline();

    return () => {
      abortRef.current?.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [iocType, iocValue, context]);

  const resetStages = () => {
    setStages(
      STAGE_DEFS.map((s, i) => ({
        stage: i,
        status: 'waiting',
        label: s.label,
        detail: '',
      }))
    );
  };

  const activateStage = (idx: number, detail = '') => {
    setStages((prev) =>
      prev.map((s, i) => {
        if (i < idx) {
          return { ...s, status: 'complete' };
        }
        if (i === idx) {
          return { ...s, status: 'active', detail };
        }
        return { ...s, status: 'waiting' };
      })
    );
  };

  const completeStage = (idx: number, detail = '') => {
    setStages((prev) =>
      prev.map((s, i) => {
        if (i < idx) {
          return { ...s, status: 'complete' };
        }
        if (i === idx) {
          return { ...s, status: 'complete', detail };
        }
        return s;
      })
    );
  };

  const completeAllStages = (details?: string[]) => {
    setStages((prev) =>
      prev.map((s, i) => ({
        ...s,
        status: 'complete',
        detail: details?.[i] || s.detail,
      }))
    );
  };

  const runPipeline = async () => {
    setIsRunning(true);
    setPipelineError(null);
    resetStages();

    const token = localStorage.getItem('token');
    abortRef.current = new AbortController();

    try {
      activateStage(0, 'Submitting IOC for enrichment...');
      await new Promise((resolve) => setTimeout(resolve, 250));

      const response = await fetch('http://localhost:8000/api/ioc/submit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          ioc_type: iocType,
          ioc_value: iocValue,
          context: context || '',
        }),
        signal: abortRef.current.signal,
      });

      if (!response.ok) {
        let errorMessage = `Pipeline returned ${response.status}`;
        try {
          const errPayload = await response.json();
          errorMessage =
            errPayload?.detail ||
            errPayload?.message ||
            errPayload?.error ||
            errorMessage;
        } catch {
          // ignore JSON parse failure
        }
        throw new Error(errorMessage);
      }

      const payload = await response.json();

      completeStage(0, 'IOC enrichment complete');
      activateStage(1, 'Mapping to MITRE ATT&CK...');
      await new Promise((resolve) => setTimeout(resolve, 250));

      completeStage(
        1,
        Array.isArray(payload?.techniques) && payload.techniques.length > 0
          ? `${payload.techniques.length} technique(s) mapped`
          : 'MITRE ATT&CK mapping complete'
      );

      activateStage(2, 'Validating mapped techniques...');
      await new Promise((resolve) => setTimeout(resolve, 250));

      const validatedCount = Array.isArray(payload?.validated_techniques)
        ? payload.validated_techniques.length
        : 0;

      completeStage(
        2,
        validatedCount > 0
          ? `${validatedCount} validated technique(s)`
          : 'Validation complete'
      );

      activateStage(3, 'Generating detection rules...');
      await new Promise((resolve) => setTimeout(resolve, 250));

      const ruleCount = Array.isArray(payload?.candidate_rules)
        ? payload.candidate_rules.length
        : 0;

      completeStage(
        3,
        ruleCount > 0
          ? `${ruleCount} detection rule(s) generated`
          : 'Detection rule generation complete'
      );

      activateStage(4, 'Finalizing analysis...');
      await new Promise((resolve) => setTimeout(resolve, 250));

      const aptHint =
        payload?.primary_technique &&
        typeof payload.primary_technique === 'object' &&
        'id' in payload.primary_technique
          ? `Primary technique: ${String(payload.primary_technique.id)}`
          : 'Analysis complete';

      completeStage(4, aptHint);

      completeAllStages([
        'IOC enrichment complete',
        Array.isArray(payload?.techniques) && payload.techniques.length > 0
          ? `${payload.techniques.length} technique(s) mapped`
          : 'MITRE ATT&CK mapping complete',
        validatedCount > 0
          ? `${validatedCount} validated technique(s)`
          : 'Validation complete',
        ruleCount > 0
          ? `${ruleCount} detection rule(s) generated`
          : 'Detection rule generation complete',
        aptHint,
      ]);

      setIsRunning(false);
      onComplete(payload);
    } catch (err: unknown) {
      if ((err as Error).name === 'AbortError') {
        return;
      }

      setPipelineError((err as Error).message || 'Pipeline connection failed.');
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-3">
      {pipelineError && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm px-4 py-3 rounded-lg flex items-center gap-2 mb-2">
          <svg
            className="w-4 h-4 flex-shrink-0"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <circle cx="12" cy="12" r="10" />
            <path d="M12 8v4m0 4h.01" />
          </svg>
          {pipelineError}
        </div>
      )}

      {stages.map((stage, i) => {
        const def = STAGE_DEFS[i];
        const isWaiting = stage.status === 'waiting';
        const isActive = stage.status === 'active';
        const isDone = stage.status === 'complete';

        return (
          <div key={i}>
            <div
              className={`rounded-lg border px-4 py-3.5 transition-all duration-500 ${
                isDone
                  ? 'border-green-500/30 bg-green-500/5'
                  : isActive
                  ? 'border-amber-500/40 bg-amber-500/5 pipeline-pulse'
                  : 'border-white/[0.06] bg-[#0a0f1e]'
              }`}
            >
              <div className="flex items-center gap-3">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 text-base ${
                    isDone
                      ? 'bg-green-500/15 border border-green-500/30'
                      : isActive
                      ? 'bg-amber-500/15 border border-amber-500/30'
                      : 'bg-white/[0.04] border border-white/[0.08]'
                  }`}
                >
                  {isDone ? (
                    <svg
                      className="w-4 h-4 text-green-400"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth={2.5}
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        d="M5 13l4 4L19 7"
                      />
                    </svg>
                  ) : isActive ? (
                    <svg
                      className="w-4 h-4 text-amber-400 spin"
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth={2}
                    >
                      <path d="M21 12a9 9 0 11-6.219-8.56" />
                    </svg>
                  ) : (
                    <span className="text-slate-600 text-xs">{def.icon}</span>
                  )}
                </div>

                <div className="flex-1 min-w-0">
                  <p
                    className={`text-sm font-semibold ${
                      isDone
                        ? 'text-green-300'
                        : isActive
                        ? 'text-amber-300'
                        : 'text-slate-500'
                    }`}
                  >
                    {stage.label}
                  </p>

                  {isDone && stage.detail && (
                    <p className="text-xs text-slate-400 mt-0.5 truncate">
                      {stage.detail}
                    </p>
                  )}

                  {isActive && (
                    <p className="text-xs text-amber-500/70 mt-0.5">
                      {stage.detail || 'Analyzing...'}
                    </p>
                  )}

                  {isWaiting && !isActive && !isDone && (
                    <p className="text-xs text-slate-600 mt-0.5">
                      Waiting...
                    </p>
                  )}
                </div>

                <span
                  className={`text-xs px-2 py-0.5 rounded-full border flex-shrink-0 ${
                    isDone
                      ? 'bg-green-500/10 border-green-500/20 text-green-400'
                      : isActive
                      ? 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                      : 'bg-white/[0.04] border-white/[0.06] text-slate-600'
                  }`}
                >
                  {isDone ? 'Complete' : isActive ? 'Running' : 'Waiting'}
                </span>
              </div>
            </div>

            {i < stages.length - 1 && (
              <div className="flex justify-center py-1">
                <div
                  className={`w-px h-4 transition-colors duration-500 ${
                    isDone ? 'bg-green-500/30' : 'bg-white/[0.06]'
                  }`}
                />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
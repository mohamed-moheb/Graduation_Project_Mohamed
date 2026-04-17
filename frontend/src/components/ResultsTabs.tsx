import { useEffect, useState } from 'react';
import api from '../api/client';
import type { PipelineResult, TechniqueResult, WazuhRule, CandidateApt } from '../types';

interface ResultsTabsProps {
  results: PipelineResult;
  iocType?: string;
  iocValue?: string;
  context?: string;
  submissionId?: number;
}

type AptStep = 'list' | 'loading' | 'prediction' | 'rules';

interface AptProjectionResult {
  predicted_next_step?: {
    predicted_next_technique?: {
      id?: string;
      name?: string;
      tactic?: string;
      why_this_is_next?: string;
    };
    confidence?: {
      score?: number;
      level?: string;
      justification?: string;
    };
  };
  predicted_rules?: WazuhRule[];
  selected_apt?: { apt_name?: string };
  source?: string;
  error?: string;
  [key: string]: unknown;
}

function tacticColor(tactics?: string[]): string {
  if (!tactics?.length) return 'bg-slate-500';
  const t = tactics[0].toLowerCase();
  if (t.includes('execution'))       return 'bg-blue-500';
  if (t.includes('persistence'))     return 'bg-purple-500';
  if (t.includes('defense-evasion')) return 'bg-slate-400';
  if (t.includes('credential'))      return 'bg-red-500';
  if (t.includes('discovery'))       return 'bg-cyan-500';
  if (t.includes('lateral'))         return 'bg-orange-500';
  if (t.includes('command'))         return 'bg-pink-500';
  if (t.includes('exfiltration'))    return 'bg-amber-500';
  if (t.includes('impact'))          return 'bg-rose-500';
  if (t.includes('initial'))         return 'bg-teal-500';
  if (t.includes('privilege'))       return 'bg-violet-500';
  if (t.includes('collection'))      return 'bg-indigo-500';
  return 'bg-slate-500';
}

function levelBadgeClass(level?: string) {
  const l = (level || '').toLowerCase();
  if (l === 'high')   return 'bg-green-500/10 border-green-500/30 text-green-400';
  if (l === 'medium') return 'bg-amber-500/10 border-amber-500/30 text-amber-400';
  return                     'bg-red-500/10  border-red-500/30  text-red-400';
}

function riskBadgeClass(level?: string) {
  const l = (level || '').toLowerCase();
  if (l === 'critical') return 'bg-red-500/10 border-red-500/30 text-red-400';
  if (l === 'high')     return 'bg-orange-500/10 border-orange-500/30 text-orange-400';
  if (l === 'medium')   return 'bg-amber-500/10 border-amber-500/30 text-amber-400';
  if (l === 'low')      return 'bg-green-500/10 border-green-500/30 text-green-400';
  return                       'bg-slate-500/10 border-slate-500/30 text-slate-400';
}

function levelColor(level?: string) {
  const l = (level || '').toLowerCase();
  if (l === 'critical') return 'text-red-400';
  if (l === 'high')     return 'text-orange-400';
  if (l === 'medium')   return 'text-amber-400';
  if (l === 'low')      return 'text-green-400';
  return 'text-slate-400';
}

function RuleBlock({ rule, index }: { rule: WazuhRule; index: number }) {
  const xmlContent = rule.wazuh_xml || JSON.stringify(rule, null, 2);
  const [copied, setCopied] = useState(false);

  return (
    <div className="bg-[#0a0f1e] border border-white/[0.06] rounded-lg overflow-hidden">
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-white/[0.06] bg-[#0d1525]">
        <span className="font-mono text-amber-400 text-xs font-bold">#{rule.rule_id ?? index + 1}</span>
        {rule.description && <span className="text-slate-300 text-xs flex-1 truncate">{rule.description}</span>}
        <div className="flex items-center gap-2 ml-auto">
          {(rule as Record<string, unknown>).wazuh_level !== undefined && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-orange-500/10 border border-orange-500/20 text-orange-400">
              Level {(rule as Record<string, unknown>).wazuh_level as number}
            </span>
          )}
          {rule.mitre?.map((m, mi) => (
            <span key={mi} className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 font-mono">{m}</span>
          ))}
          {(rule as Record<string, unknown>).candidate_type === 'proactive_blueprint' && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-pink-500/10 border border-pink-500/20 text-pink-400">Proactive</span>
          )}
          <button
            onClick={() => navigator.clipboard.writeText(xmlContent).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); })}
            className="flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-white/[0.04] border border-white/[0.06] text-slate-400 hover:text-white transition-colors"
          >
            {copied
              ? <><svg className="w-3 h-3 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path d="M5 13l4 4L19 7"/></svg><span className="text-green-400">Copied</span></>
              : <><svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>Copy</>
            }
          </button>
        </div>
      </div>
      <pre className={`text-xs leading-relaxed p-4 overflow-x-auto max-h-48 overflow-y-auto ${rule.wazuh_xml ? 'text-green-300' : 'text-slate-400'}`}>
        <code>{xmlContent}</code>
      </pre>
    </div>
  );
}

export default function ResultsTabs({ results, iocType, iocValue, context, submissionId }: ResultsTabsProps) {
  const [activeTab, setActiveTab] = useState<'techniques' | 'rules' | 'apt'>('techniques');

  const [aptStep,          setAptStep]         = useState<AptStep>('list');
  const [selectedApt,      setSelectedApt]     = useState<CandidateApt | null>(null);
  const [projectionResult, setProjection]      = useState<AptProjectionResult | null>(null);
  const [projectionError,  setProjectionErr]   = useState<string | null>(null);

  const [localCandidateApts, setLocalCandidateApts] = useState<CandidateApt[]>([]);
  const [loadingApts,        setLoadingApts]        = useState(false);
  const [aptCandidateError,  setAptCandidateError]  = useState<string | null>(null);

  const techniques: TechniqueResult[] = (results.techniques || []).map((t) => {
  if (typeof t === 'string') return { id: t };
  return {
    id:         String(t.id   || ''),
    name:       t.name       || undefined,
    reason:     t.reason     || undefined,
    tactics:    Array.isArray(t.tactics) ? t.tactics : undefined,
    rule_count: typeof t.rule_count === 'number' ? t.rule_count : undefined,
  };
}).filter(t => t.id);

  const validatedIds = new Set<string>(
    Array.isArray(results.validated_techniques)
      ? results.validated_techniques.map(t => (typeof t === 'string' ? t : t.id))
      : []
  );

  const rawRules = Array.isArray(results.candidate_rules) && results.candidate_rules.length > 0
    ? results.candidate_rules
    : (results.detection_rules ?? null);

  const rules: WazuhRule[] = (() => {
    if (!rawRules) return [];
    if (Array.isArray(rawRules)) return rawRules as WazuhRule[];
    if (typeof rawRules === 'string') { try { return JSON.parse(rawRules); } catch { return [{ wazuh_xml: rawRules }]; } }
    return [];
  })();

  const candidateApts: CandidateApt[] = (() => {
    const raw = results.candidate_apts || results.apt_groups || results.apts;
    if (!Array.isArray(raw) || raw.length === 0) return [];
    return raw.map(item =>
      typeof item === 'string'
        ? { apt_name: item, matching_techniques: 0, total_known_techniques: 0 }
        : (item as CandidateApt)
    );
  })();

  const conf      = results.confidence_metrics as Record<string, number> | undefined;
  const riskScore = results.risk_score;
  const riskLevel = results.risk_level;
  const displayApts = localCandidateApts.length > 0 ? localCandidateApts : candidateApts;

  const tabs = [
    { id: 'techniques' as const, label: 'Techniques',      count: techniques.length },
    { id: 'rules'      as const, label: 'Detection Rules', count: rules.length || null },
    { id: 'apt'        as const, label: 'APT Projection',  count: displayApts.length || null },
  ];

  // ── APT projection + save to DB ───────────────────────────────────────────
  const handlePredict = async (apt: CandidateApt) => {
    if (!iocType || !iocValue) return;
    setSelectedApt(apt);
    setAptStep('loading');
    setProjectionErr(null);
    try {
      const res = await api.post<AptProjectionResult>('/api/ioc/apt-projection', {
        ioc_type:     iocType,
        ioc_value:    iocValue,
        context:      context || '',
        selected_apt: apt.apt_name,
      });
      if (res.data.error) {
        setProjectionErr(res.data.error as string);
        setAptStep('list');
      } else {
        setProjection(res.data);
        setAptStep('prediction');
      

        // ── Save APT projection to DB so AdminRules can display proactive rules ──
        if (submissionId) {
          try {
            await api.post('/submissions/save-apt-projection', {
              submission_id:         submissionId,
              apt_projection_result: res.data,
            });
          } catch {
            // non-critical — don't break the UI
          }
        }
      }
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setProjectionErr(msg || 'Projection failed. Try again.');
      setAptStep('list');
    }
  };

  const resetApt = () => {
    setAptStep('list');
    setSelectedApt(null);
    setProjection(null);
    setProjectionErr(null);
  };

  // Fetch candidate APTs when tab first opened
  useEffect(() => {
    if (activeTab !== 'apt') return;
    if (loadingApts || localCandidateApts.length > 0 || aptCandidateError) return;
    const techIds = techniques.map(t => t.id).filter(Boolean);
    if (!techIds.length) return;
    setLoadingApts(true);
    setAptCandidateError(null);
    api.post<{ candidate_apts: CandidateApt[] }>('/api/ioc/candidates', { mapped_techniques: techIds })
      .then(res => setLocalCandidateApts(res.data.candidate_apts || []))
      .catch(() => setAptCandidateError('Failed to load APT candidates.'))
      .finally(() => setLoadingApts(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div>
      {/* Risk / confidence banner */}
      {riskScore !== undefined && (
        <div className="flex items-center gap-4 bg-[#0a0f1e] border border-white/[0.06] rounded-lg px-4 py-3 mb-4 flex-wrap gap-y-2">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Risk</span>
            <span className={`text-lg font-bold ${levelColor(riskLevel)}`}>{riskScore}</span>
            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${riskBadgeClass(riskLevel)}`}>{riskLevel}</span>
          </div>
          {conf && (
            <div className="flex items-center gap-4 ml-auto">
              {[
                { label: 'LLM',     val: conf.model_reliability },
                { label: 'RAG',     val: conf.rag_validation },
                { label: 'Intel',   val: conf.external_intel_agreement },
                { label: 'Overall', val: conf.overall_threat_confidence },
              ].map(m => (
                <div key={m.label} className="text-center">
                  <div className="text-xs text-slate-500">{m.label}</div>
                  <div className="text-sm font-bold text-white">{m.val !== undefined ? `${m.val}%` : '—'}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab header */}
      <div className="flex gap-1 border-b border-white/[0.07] mb-4">
        {tabs.map(tab => (
          <button key={tab.id} onClick={() => { setActiveTab(tab.id); if (tab.id === 'apt') resetApt(); }}
            className={`px-4 py-2.5 text-sm font-medium rounded-t-lg transition-all duration-150 flex items-center gap-2 ${
              activeTab === tab.id ? 'text-blue-400 border-b-2 border-blue-500 bg-blue-500/5' : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
            }`}>
            {tab.label}
            {tab.count !== null && tab.count !== undefined && tab.count > 0 && (
              <span className={`text-xs px-1.5 py-0.5 rounded-full ${activeTab === tab.id ? 'bg-blue-500/20 text-blue-400' : 'bg-white/[0.08] text-slate-400'}`}>
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── TECHNIQUES TAB ────────────────────────────────────────────────── */}
      {activeTab === 'techniques' && (
        <div className="space-y-2">
          {techniques.length === 0 ? (
            <p className="text-slate-500 text-sm py-8 text-center">No techniques mapped.</p>
          ) : (
            techniques.map((tech, i) => {
              const isValidated = validatedIds.has(tech.id);
              return (
                <div key={`${tech.id}-${i}`} className="bg-[#0a0f1e] border border-white/[0.06] rounded-lg px-4 py-3">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="font-mono text-blue-400 text-sm font-semibold">{tech.id}</span>
                    {tech.name && <span className="text-white text-sm">{tech.name}</span>}
                    {isValidated && (
                      <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-green-500/10 border border-green-500/25 text-green-400 font-medium">
                        <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7"/></svg>
                        Validated
                      </span>
                    )}
                    {tech.tactics?.map((t, ti) => (
                      <span key={ti} className="text-xs px-2 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400">{t}</span>
                    ))}
                  </div>
                  {tech.reason && <p className="text-slate-400 text-xs leading-relaxed">{tech.reason}</p>}
                </div>
              );
            })
          )}
        </div>
      )}

      {/* ── DETECTION RULES TAB ───────────────────────────────────────────── */}
      {activeTab === 'rules' && (
        <div className="space-y-3">
          {rules.length === 0 ? (
            <p className="text-slate-500 text-sm py-8 text-center">No detection rules generated.</p>
          ) : (
            rules.map((rule, i) => <RuleBlock key={rule.rule_id ?? i} rule={rule} index={i} />)
          )}
        </div>
      )}

      {/* ── APT PROJECTION TAB ────────────────────────────────────────────── */}
      {activeTab === 'apt' && (
        <div>
          {/* STEP 1 — APT LIST */}
          {aptStep === 'list' && (
            <div className="space-y-3">
              {projectionError && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-xs px-4 py-3 rounded-lg">{projectionError}</div>
              )}
              {loadingApts && (
                <div className="py-8 flex flex-col items-center gap-3">
                  <svg className="w-6 h-6 spin text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M21 12a9 9 0 11-6.219-8.56"/></svg>
                  <p className="text-slate-500 text-xs">Loading candidate APT groups...</p>
                </div>
              )}
              {!loadingApts && aptCandidateError && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-xs px-4 py-3 rounded-lg">{aptCandidateError}</div>
              )}
              {!loadingApts && !aptCandidateError && techniques.length === 0 && (
                <p className="text-slate-500 text-sm py-8 text-center">No techniques detected — APT matching requires at least one mapped technique.</p>
              )}
              {!loadingApts && !aptCandidateError && techniques.length > 0 && displayApts.length === 0 && (
                <p className="text-slate-500 text-sm py-8 text-center">No APT groups matched the detected techniques.</p>
              )}
              {!loadingApts && displayApts.length > 0 && (
                <>
                  <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-1">Candidate Threat Actors</p>
                  {displayApts.map((apt, i) => {
                    const pct = apt.total_known_techniques > 0
                      ? Math.round((apt.matching_techniques / apt.total_known_techniques) * 100) : 0;
                    return (
                      <div key={i} className="bg-red-500/5 border border-red-500/20 rounded-lg px-4 py-3">
                        <div className="flex items-center justify-between gap-3 mb-2">
                          <div className="flex items-center gap-2">
                            <svg className="w-4 h-4 text-red-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                              <path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                            </svg>
                            <span className="text-red-300 text-sm font-semibold">{apt.apt_name}</span>
                          </div>
                          {iocType && iocValue && (
                            <button onClick={() => handlePredict(apt)}
                              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-purple-600/20 border border-purple-500/30 text-purple-300 hover:bg-purple-600/30 transition-colors flex-shrink-0">
                              Predict Next Step
                              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6"/></svg>
                            </button>
                          )}
                        </div>
                        {apt.total_known_techniques > 0 && (
                          <div>
                            <div className="flex items-center justify-between text-xs mb-1">
                              <span className="text-slate-500">
                                {apt.matching_techniques} technique{apt.matching_techniques !== 1 ? 's' : ''} in common
                                <span className="text-slate-600"> / {apt.total_known_techniques} known</span>
                              </span>
                              <span className="text-slate-400 font-mono">{pct}%</span>
                            </div>
                            <div className="h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                              <div className="h-full bg-red-500/60 rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </>
              )}
            </div>
          )}

          {/* STEP 2 — LOADING */}
          {aptStep === 'loading' && (
            <div className="py-12 flex flex-col items-center gap-4">
              <svg className="w-8 h-8 spin text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M21 12a9 9 0 11-6.219-8.56"/></svg>
              <div className="text-center">
                <p className="text-white text-sm font-medium">Predicting next technique...</p>
                <p className="text-slate-500 text-xs mt-1">Querying threat intelligence for <span className="text-purple-300">{selectedApt?.apt_name}</span></p>
              </div>
            </div>
          )}

          {/* STEP 3 — PREDICTION */}
          {aptStep === 'prediction' && projectionResult && (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <button onClick={resetApt} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors">
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>
                  Back
                </button>
                <span className="text-xs text-slate-500">Prediction for</span>
                <span className="text-xs font-semibold text-red-300 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded-full">{selectedApt?.apt_name}</span>
                {submissionId && <span className="text-xs text-green-400 bg-green-500/10 border border-green-500/20 px-2 py-0.5 rounded-full ml-auto">✓ Saved to DB</span>}
              </div>

              {projectionResult.predicted_next_step?.predicted_next_technique && (
                <div className="bg-purple-500/5 border border-purple-500/20 rounded-xl p-5">
                  <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-3">Predicted Next Technique</p>
                  <div className="flex items-center gap-3 mb-3 flex-wrap">
                    <span className="font-mono text-purple-400 text-xl font-bold">
                      {projectionResult.predicted_next_step.predicted_next_technique.id}
                    </span>
                    {projectionResult.predicted_next_step.predicted_next_technique.name && (
                      <span className="text-white text-sm font-medium">{projectionResult.predicted_next_step.predicted_next_technique.name}</span>
                    )}
                    {projectionResult.predicted_next_step.predicted_next_technique.tactic && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400">
                        {projectionResult.predicted_next_step.predicted_next_technique.tactic}
                      </span>
                    )}
                  </div>
                  {projectionResult.predicted_next_step.predicted_next_technique.why_this_is_next && (
                    <p className="text-slate-300 text-sm leading-relaxed">
                      {projectionResult.predicted_next_step.predicted_next_technique.why_this_is_next}
                    </p>
                  )}
                </div>
              )}

              {projectionResult.predicted_next_step?.confidence && (
                <div className="bg-[#0a0f1e] border border-white/[0.06] rounded-lg p-4">
                  <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-3">Confidence</p>
                  <div className="flex items-center gap-4 mb-2">
                    <span className={`text-2xl font-bold ${levelColor(projectionResult.predicted_next_step.confidence.level)}`}>
                      {projectionResult.predicted_next_step.confidence.score ?? '—'}%
                    </span>
                    <span className={`text-sm font-semibold px-3 py-1 rounded-full border ${levelBadgeClass(projectionResult.predicted_next_step.confidence.level)}`}>
                      {projectionResult.predicted_next_step.confidence.level}
                    </span>
                    {projectionResult.source === 'anthropic_fallback' && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 ml-auto">Anthropic Fallback</span>
                    )}
                  </div>
                  {projectionResult.predicted_next_step.confidence.justification && (
                    <p className="text-slate-400 text-xs leading-relaxed">{projectionResult.predicted_next_step.confidence.justification}</p>
                  )}
                </div>
              )}

              <button onClick={() => setAptStep('rules')}
                className="flex items-center gap-2 text-sm px-4 py-2.5 rounded-lg bg-pink-600/20 border border-pink-500/30 text-pink-300 hover:bg-pink-600/30 transition-colors">
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/></svg>
                Show Defensive Rules
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6"/></svg>
              </button>
            </div>
          )}

          {/* STEP 4 — PROACTIVE RULES */}
          {aptStep === 'rules' && projectionResult && (
            <div className="space-y-3">
              <div className="flex items-center gap-3 mb-1">
                <button onClick={() => setAptStep('prediction')} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors">
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>
                  Back to prediction
                </button>
                <span className="text-xs text-slate-500 ml-auto">Proactive rules for anticipated technique</span>
              </div>
              {!projectionResult.predicted_rules?.length ? (
                <div className="bg-[#0a0f1e] border border-white/[0.06] rounded-lg py-8 text-center text-slate-500 text-sm">
                  No blueprint rules available for this technique.
                </div>
              ) : (
                projectionResult.predicted_rules.map((rule, i) => <RuleBlock key={rule.rule_id ?? i} rule={rule} index={i} />)
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export { tacticColor };
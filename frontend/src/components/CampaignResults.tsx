import { useState } from 'react';
import api from '../api/client';
import type { Campaign, KillChainEntry, WazuhRule, CandidateApt, PipelineResult } from '../types';

// ── helpers ───────────────────────────────────────────────────────────────────
function riskColor(level?: string | null) {
  const l = (level || '').toLowerCase();
  if (l === 'critical') return 'text-red-400';
  if (l === 'high')     return 'text-orange-400';
  if (l === 'medium')   return 'text-amber-400';
  if (l === 'low')      return 'text-green-400';
  return 'text-slate-400';
}

function riskBorder(level?: string | null) {
  const l = (level || '').toLowerCase();
  if (l === 'critical') return 'border-red-500/30 bg-red-500/5';
  if (l === 'high')     return 'border-orange-500/30 bg-orange-500/5';
  if (l === 'medium')   return 'border-amber-500/30 bg-amber-500/5';
  if (l === 'low')      return 'border-green-500/30 bg-green-500/5';
  return 'border-white/[0.08] bg-white/[0.02]';
}

function levelColor(level?: string) {
  const l = (level || '').toLowerCase();
  if (l === 'high')   return 'text-green-400';
  if (l === 'medium') return 'text-amber-400';
  return 'text-red-400';
}

const TACTIC_COLORS: Record<string, string> = {
  'reconnaissance':       'bg-slate-600/30 border-slate-500/30 text-slate-300',
  'resource-development': 'bg-slate-600/30 border-slate-500/30 text-slate-300',
  'initial-access':       'bg-teal-600/30 border-teal-500/30 text-teal-300',
  'execution':            'bg-blue-600/30 border-blue-500/30 text-blue-300',
  'persistence':          'bg-purple-600/30 border-purple-500/30 text-purple-300',
  'privilege-escalation': 'bg-violet-600/30 border-violet-500/30 text-violet-300',
  'defense-evasion':      'bg-slate-500/30 border-slate-400/30 text-slate-200',
  'credential-access':    'bg-red-600/30 border-red-500/30 text-red-300',
  'discovery':            'bg-cyan-600/30 border-cyan-500/30 text-cyan-300',
  'lateral-movement':     'bg-orange-600/30 border-orange-500/30 text-orange-300',
  'collection':           'bg-indigo-600/30 border-indigo-500/30 text-indigo-300',
  'command-and-control':  'bg-pink-600/30 border-pink-500/30 text-pink-300',
  'exfiltration':         'bg-amber-600/30 border-amber-500/30 text-amber-300',
  'impact':               'bg-rose-600/30 border-rose-500/30 text-rose-300',
};

// ── IOC result normaliser ─────────────────────────────────────────────────────
// The detail endpoint (GET /api/campaign/{id}) returns ioc_results where each
// entry has result_json as an already-parsed object.
// The submit endpoint (POST /api/campaign/submit) returns ioc_results where
// techniques/candidate_rules are at the TOP LEVEL of each entry (not inside
// result_json), because those entries are raw submit_ioc() return values.
// This function normalises both shapes into a single consistent structure.
interface NormalisedIOC {
  ioc_type: string;
  ioc_value: string;
  context: string;
  techniques: Array<{ id: string; name?: string; tactics?: string[] }>;
  candidate_rules: WazuhRule[];
  risk_score?: number;
  risk_level?: string;
}

function normaliseIOC(ioc: Record<string, unknown>): NormalisedIOC {
  // Shape A: detail endpoint — result_json is an object
  const rj = ioc.result_json as PipelineResult | null | undefined;
  const source: PipelineResult = (rj && typeof rj === 'object' && !Array.isArray(rj))
    ? rj
    : (ioc as unknown as PipelineResult);

  const rawTechs = Array.isArray(source.techniques) ? source.techniques : [];
  const techniques = rawTechs.map(t =>
    typeof t === 'string'
      ? { id: t }
      : { id: String((t as { id?: unknown }).id || ''), name: (t as { name?: string }).name, tactics: (t as { tactics?: string[] }).tactics }
  ).filter(t => t.id && t.id !== 'undefined');

  const candidate_rules = Array.isArray(source.candidate_rules)
    ? source.candidate_rules as WazuhRule[]
    : [];

  return {
    ioc_type:       String(ioc.ioc_type || ''),
    ioc_value:      String(ioc.ioc_value || ''),
    context:        String(ioc.context || ''),
    techniques,
    candidate_rules,
    risk_score:  typeof source.risk_score === 'number' ? source.risk_score : undefined,
    risk_level:  typeof source.risk_level === 'string' ? source.risk_level : undefined,
  };
}

// ── Kill chain heatmap ────────────────────────────────────────────────────────
function KillChainHeatmap({ map }: { map: KillChainEntry[] }) {
  if (!map || map.length === 0) return null;
  const covered = map.filter(e => e.covered).length;
  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Kill Chain Coverage</p>
        <span className="text-xs text-slate-400">
          <span className="text-white font-semibold">{covered}</span>
          <span className="text-slate-600">/{map.length}</span> stages covered
        </span>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {map.map(entry => {
          const color = TACTIC_COLORS[entry.tactic] || 'bg-slate-600/20 border-slate-500/20 text-slate-400';
          return (
            <div
              key={entry.tactic}
              title={`${entry.tactic}: ${entry.technique_count} technique${entry.technique_count !== 1 ? 's' : ''}`}
              className={`px-2.5 py-1.5 rounded-lg border text-xs font-medium ${
                entry.covered
                  ? color
                  : 'bg-white/[0.02] border-dashed border-white/[0.08] text-slate-700'
              }`}
            >
              <span className="capitalize">{entry.tactic.replace(/-/g, ' ')}</span>
              {entry.covered && <span className="ml-1.5 opacity-60">{entry.technique_count}</span>}
            </div>
          );
        })}
      </div>
      {/* no coverage warning removed */}
    </div>
  );
}

// ── Campaign Analysis block (replaces APT candidates in overview) ─────────────
function CampaignAnalysis({ corr }: { corr: NonNullable<Campaign['correlation']> }) {
  const topApt     = corr.top_apt;
  const shared     = corr.shared_techniques ?? [];
  const allTechs   = corr.kill_chain_map?.flatMap(e => e.techniques) ?? [];
  const covered    = corr.kill_chain_map?.filter(e => e.covered) ?? [];
  const riskLevel  = corr.combined_risk_level ?? '';
  const riskScore  = corr.combined_risk_score ?? 0;

  // Build a plain-English summary
  const tacticNames = covered.map(e => e.tactic.replace(/-/g, ' ')).join(', ');
  const sharedNote  = shared.length > 0
    ? `${shared.length} technique${shared.length > 1 ? 's' : ''} (${shared.map(s => s.technique_id).join(', ')}) appear across multiple IOCs, indicating coordinated attacker behaviour.`
    : 'Each IOC maps to a distinct technique set, suggesting either a multi-stage operation with specialised tools per phase, or separate but related intrusion vectors.';

  const aptNote = topApt
    ? `The combined technique profile most closely matches ${topApt.apt_name} with ${topApt.matching_techniques} technique${topApt.matching_techniques !== 1 ? 's' : ''} in common out of ${topApt.total_known_techniques} known — a ${Math.round((topApt.matching_techniques / topApt.total_known_techniques) * 100)}% overlap.`
    : 'No strong APT group match found in the MITRE ATT&CK dataset for this technique combination.';

  const riskNote = riskScore >= 85
    ? 'The campaign poses a critical risk — immediate containment and escalation is recommended.'
    : riskScore >= 65
    ? 'The campaign poses a high risk. Priority investigation and containment steps should be initiated.'
    : riskScore >= 40
    ? 'The campaign poses a medium risk. Investigation is warranted to determine scope and intent.'
    : 'The campaign shows low risk indicators. Monitor for escalation.';

  return (
    <div className="bg-[#0a0f1e] border border-white/[0.07] rounded-xl p-5 space-y-4">
      <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Campaign Analysis</p>

      {/* Risk summary */}
      <div className="flex items-center gap-3">
        <span className={`text-3xl font-bold ${riskColor(riskLevel)}`}>{riskScore}</span>
        <div>
          <span className={`text-sm font-semibold ${riskColor(riskLevel)}`}>{riskLevel} Risk</span>
          <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">{riskNote}</p>
        </div>
      </div>

      {/* Kill chain summary */}
      {tacticNames && (
        <div>
          <p className="text-xs text-slate-500 font-semibold mb-1">Kill Chain Stages Observed</p>
          <p className="text-xs text-slate-300 leading-relaxed">
            This campaign spans <span className="text-white font-semibold">{covered.length}</span> kill chain stage{covered.length !== 1 ? 's' : ''}
            {' '}({tacticNames}), covering <span className="text-white font-semibold">{allTechs.length}</span> unique technique{allTechs.length !== 1 ? 's' : ''} in total.
          </p>
        </div>
      )}

      {/* Technique correlation */}
      <div>
        <p className="text-xs text-slate-500 font-semibold mb-1">IOC Correlation</p>
        <p className="text-xs text-slate-300 leading-relaxed">{sharedNote}</p>
      </div>

      {/* APT attribution */}
      <div>
        <p className="text-xs text-slate-500 font-semibold mb-1">Threat Actor Attribution</p>
        <p className="text-xs text-slate-300 leading-relaxed">{aptNote}</p>
        {topApt && (
          <div className="mt-2 flex items-center gap-3">
            <div className="flex-1 h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
              <div
                className="h-full bg-red-500/60 rounded-full"
                style={{ width: `${Math.round((topApt.matching_techniques / topApt.total_known_techniques) * 100)}%` }}
              />
            </div>
            <span className="text-xs font-mono text-red-300 flex-shrink-0">{topApt.apt_name}</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Rule block ────────────────────────────────────────────────────────────────
function RuleBlock({ rule, index }: { rule: WazuhRule; index: number }) {
  const [open,   setOpen]   = useState(false);
  const [copied, setCopied] = useState(false);
  const xml = rule.wazuh_xml || JSON.stringify(rule, null, 2);

  return (
    <div className="bg-[#080d1a] border border-white/[0.06] rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-white/[0.05]">
        <span className="font-mono text-amber-400 text-xs">#{rule.rule_id ?? index + 1}</span>
        {rule.description && <span className="text-slate-400 text-xs flex-1 truncate">{rule.description}</span>}
        <div className="flex items-center gap-1.5 ml-auto flex-shrink-0">
          {(rule.candidate_type === 'proactive_blueprint' || rule.candidate_type === 'campaign_proactive') && (
            <span className="text-xs px-1.5 py-0.5 rounded bg-pink-500/10 border border-pink-500/20 text-pink-400">Proactive</span>
          )}
          {rule.mitre?.map((m, i) => (
            <span key={i} className="font-mono text-xs px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">{m}</span>
          ))}
          <button
            onClick={() => navigator.clipboard.writeText(xml).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); })}
            className="text-xs px-2 py-0.5 rounded bg-white/[0.04] border border-white/[0.06] text-slate-400 hover:text-white transition-colors"
          >
            {copied ? <span className="text-green-400">Copied</span> : 'Copy'}
          </button>
          <button onClick={() => setOpen(v => !v)} className="text-slate-600 hover:text-white transition-colors">
            <svg className={`w-4 h-4 transition-transform ${open ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/>
            </svg>
          </button>
        </div>
      </div>
      {open && (
        <pre className="text-xs text-green-300 leading-relaxed p-3 overflow-x-auto max-h-48 overflow-y-auto">
          <code>{xml}</code>
        </pre>
      )}
    </div>
  );
}

// ── APT Projection tab ────────────────────────────────────────────────────────
type AptStep = 'list' | 'loading' | 'prediction';

interface ProjectionResult {
  selected_apt?: CandidateApt;
  all_techniques?: string[];
  predicted_next_step?: {
    predicted_next_technique?: { id?: string; name?: string; tactic?: string; why_this_is_next?: string };
    confidence?: { score?: number; level?: string; justification?: string };
    source?: string;
  };
  predicted_rules?: WazuhRule[];
}

function CampaignAptProjection({ campaign }: { campaign: Campaign }) {
  const corr = campaign.correlation;
  const existingProjection = corr?.campaign_apt_projection as ProjectionResult | undefined;

  const [aptStep,     setAptStep]    = useState<AptStep>(existingProjection ? 'prediction' : 'list');
  const [selectedApt, setSelectedApt] = useState<CandidateApt | null>(existingProjection?.selected_apt ?? null);
  const [projection,  setProjection]  = useState<ProjectionResult | null>(existingProjection ?? null);
  const [projError,   setProjError]   = useState<string | null>(null);

  const aptCandidates = corr?.campaign_apt_candidates ?? [];

  const handlePredict = async (apt: CandidateApt) => {
    setSelectedApt(apt);
    setAptStep('loading');
    setProjError(null);
    try {
      const res = await api.post<ProjectionResult>(
        `/api/campaign/${campaign.campaign_id}/apt-projection`,
        { selected_apt: apt.apt_name }
      );
      setProjection(res.data);
      setAptStep('prediction');
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      setProjError(msg || 'Projection failed. Try again.');
      setAptStep('list');
    }
  };

  const reset = () => { setAptStep('list'); setSelectedApt(null); setProjection(null); setProjError(null); };

  if (aptStep === 'list') {
    return (
      <div className="space-y-3">
        <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg px-4 py-3 text-xs text-blue-300">
          Select an APT group to predict the next attack technique across the entire campaign's combined technique set.
        </div>
        {projError && (
          <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-xs px-4 py-3 rounded-lg">{projError}</div>
        )}
        {aptCandidates.length === 0 ? (
          <p className="text-slate-500 text-sm py-8 text-center">No APT groups matched the combined technique set.</p>
        ) : (
          <>
            <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold">
              Campaign Threat Actors — based on {corr?.total_unique_techniques ?? 0} combined techniques
            </p>
            {aptCandidates.map((apt, i) => {
              const pct = apt.total_known_techniques > 0 ? Math.round((apt.matching_techniques / apt.total_known_techniques) * 100) : 0;
              return (
                <div key={i} className="bg-red-500/5 border border-red-500/20 rounded-lg px-4 py-3">
                  <div className="flex items-center justify-between gap-3 mb-2">
                    <div className="flex items-center gap-2">
                      <svg className="w-4 h-4 text-red-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
                      </svg>
                      <span className="text-red-300 text-sm font-semibold">{apt.apt_name}</span>
                      {i === 0 && <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/20 border border-red-500/30 text-red-300">Best match</span>}
                    </div>
                    <button
                      onClick={() => handlePredict(apt)}
                      className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-purple-600/20 border border-purple-500/30 text-purple-300 hover:bg-purple-600/30 transition-colors flex-shrink-0"
                    >
                      Predict Next Step
                      <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6"/>
                      </svg>
                    </button>
                  </div>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="text-slate-500">{apt.matching_techniques} in common<span className="text-slate-600"> / {apt.total_known_techniques} known</span></span>
                    <span className="text-slate-400 font-mono">{pct}%</span>
                  </div>
                  <div className="h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                    <div className="h-full bg-red-500/60 rounded-full transition-all" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </>
        )}
      </div>
    );
  }

  if (aptStep === 'loading') {
    return (
      <div className="py-12 flex flex-col items-center gap-4">
        <svg className="w-8 h-8 spin text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path d="M21 12a9 9 0 11-6.219-8.56"/>
        </svg>
        <div className="text-center">
          <p className="text-white text-sm font-medium">Predicting next campaign technique...</p>
          <p className="text-slate-500 text-xs mt-1">Analyzing {corr?.total_unique_techniques ?? 0} combined techniques for <span className="text-purple-300">{selectedApt?.apt_name}</span></p>
        </div>
      </div>
    );
  }

  if (aptStep === 'prediction' && projection) {
    const pnt   = projection.predicted_next_step?.predicted_next_technique;
    const conf  = projection.predicted_next_step?.confidence;
    const src   = projection.predicted_next_step?.source;
    const rules = projection.predicted_rules ?? [];

    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <button onClick={reset} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors">
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
            </svg>
            Back
          </button>
          <span className="text-xs text-slate-500">Campaign projection for</span>
          <span className="text-xs font-semibold text-red-300 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded-full">
            {projection.selected_apt?.apt_name ?? selectedApt?.apt_name}
          </span>
          {src === 'anthropic_fallback' && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 ml-auto">Anthropic Fallback</span>
          )}
        </div>

        {projection.all_techniques && projection.all_techniques.length > 0 && (
          <div className="bg-[#0a0f1e] border border-white/[0.06] rounded-lg px-4 py-3">
            <p className="text-xs text-slate-500 uppercase font-semibold tracking-wider mb-2">Combined Techniques ({projection.all_techniques.length})</p>
            <div className="flex flex-wrap gap-1.5">
              {projection.all_techniques.map(tid => (
                <span key={tid} className="font-mono text-xs px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">{tid}</span>
              ))}
            </div>
          </div>
        )}

        {pnt && (
          <div className="bg-purple-500/5 border border-purple-500/20 rounded-xl p-5">
            <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-3">Predicted Next Technique</p>
            <div className="flex items-center gap-3 mb-3 flex-wrap">
              <span className="font-mono text-purple-400 text-2xl font-bold">{pnt.id}</span>
              {pnt.name && <span className="text-white text-sm font-medium">{pnt.name}</span>}
              {pnt.tactic && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400">{pnt.tactic}</span>
              )}
            </div>
            {pnt.why_this_is_next && <p className="text-slate-300 text-sm leading-relaxed">{pnt.why_this_is_next}</p>}
          </div>
        )}

        {conf && (
          <div className="bg-[#0a0f1e] border border-white/[0.06] rounded-lg p-4">
            <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-3">Confidence</p>
            <div className="flex items-center gap-4">
              <span className={`text-2xl font-bold ${levelColor(conf.level)}`}>{conf.score ?? '—'}%</span>
              <span className={`text-sm font-semibold px-3 py-1 rounded-full border ${
                conf.level === 'High'   ? 'bg-green-500/10 border-green-500/30 text-green-400' :
                conf.level === 'Medium' ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
                                          'bg-red-500/10 border-red-500/30 text-red-400'
              }`}>{conf.level}</span>
            </div>
            {conf.justification && <p className="text-slate-400 text-xs leading-relaxed mt-2">{conf.justification}</p>}
          </div>
        )}

        <div>
          <div className="flex items-center justify-between mb-3">
            <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Proactive Rules ({rules.length})</p>
            <span className="text-xs text-slate-600">Deploy before {pnt?.id} is observed</span>
          </div>
          {rules.length === 0 ? (
            <div className="bg-[#0a0f1e] border border-white/[0.06] rounded-lg py-8 text-center text-slate-500 text-sm">
              No blueprint rules available for this technique.
            </div>
          ) : (
            <div className="space-y-2">
              {rules.map((rule, i) => <RuleBlock key={rule.rule_id ?? i} rule={rule} index={i} />)}
            </div>
          )}
        </div>
      </div>
    );
  }

  return null;
}

// ── Main component ────────────────────────────────────────────────────────────
interface Props { campaign: Campaign; }

export default function CampaignResults({ campaign }: Props) {
  const [activeTab, setActiveTab] = useState<'overview' | 'iocs' | 'rules' | 'apt'>('overview');
  const corr = campaign.correlation;

  const iocCount  = campaign.analyzed_count ?? corr?.total_iocs ?? campaign.ioc_count ?? 0;
  const ruleCount = corr?.unified_rule_count ?? 0;

  // Normalise ioc_results — handles both POST submit shape and GET detail shape
  const normalisedIOCs: NormalisedIOC[] = (campaign.ioc_results ?? []).map(
    ioc => normaliseIOC(ioc as unknown as Record<string, unknown>)
  );

  const tabs = [
    { id: 'overview' as const, label: 'Correlation Overview' },
    { id: 'iocs'     as const, label: `IOC Results (${iocCount})` },
    { id: 'rules'    as const, label: `Unified Rules (${ruleCount})` },
    { id: 'apt'      as const, label: 'APT Projection' },
  ];

  return (
    <div className="space-y-4">

      {/* Summary banner */}
      {corr && (
        <div className={`flex flex-wrap items-center gap-6 border rounded-xl px-5 py-4 ${riskBorder(corr.combined_risk_level)}`}>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Campaign Risk</span>
            <span className={`text-2xl font-bold ${riskColor(corr.combined_risk_level)}`}>{corr.combined_risk_score}</span>
            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${riskBorder(corr.combined_risk_level)} ${riskColor(corr.combined_risk_level)}`}>
              {corr.combined_risk_level}
            </span>
          </div>
          <div className="flex items-center gap-4 text-center ml-auto flex-wrap gap-y-2">
            {[
              { label: 'IOCs',       val: corr.total_iocs },
              { label: 'Techniques', val: corr.total_unique_techniques },
              { label: 'Shared',     val: (corr.shared_techniques ?? []).length },
              { label: 'Rules',      val: ruleCount },
            ].map(s => (
              <div key={s.label}>
                <div className="text-xs text-slate-500">{s.label}</div>
                <div className="text-sm font-bold text-white">{s.val}</div>
              </div>
            ))}
            {corr.top_apt && (
              <div>
                <div className="text-xs text-slate-500">Top APT</div>
                <div className="text-sm font-bold text-red-300">{corr.top_apt.apt_name}</div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Failed IOCs warning */}
      {campaign.failed_iocs && campaign.failed_iocs.length > 0 && (
        <div className="bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs px-4 py-3 rounded-lg">
          {campaign.failed_iocs.length} IOC(s) failed to analyze: {campaign.failed_iocs.map(f => f.ioc_value).join(', ')}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-white/[0.07]">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2.5 text-sm font-medium rounded-t-lg transition-all ${
              activeTab === tab.id
                ? 'text-blue-400 border-b-2 border-blue-500 bg-blue-500/5'
                : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── OVERVIEW TAB ─────────────────────────────────────────────────────── */}
      {activeTab === 'overview' && corr && (
        <div className="space-y-5">
          {corr.kill_chain_map && <KillChainHeatmap map={corr.kill_chain_map} />}

          {/* Campaign analysis — replaces APT candidates list in overview */}
          <CampaignAnalysis corr={corr} />

          {/* Shared techniques — only when present */}
          {(corr.shared_techniques ?? []).length > 0 && (
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-3">
                Shared Techniques — appear in multiple IOCs
              </p>
              <div className="space-y-2">
                {(corr.shared_techniques ?? []).map(st => (
                  <div key={st.technique_id} className="bg-[#0a0f1e] border border-white/[0.06] rounded-lg px-4 py-2.5 flex items-center gap-3">
                    <span className="font-mono text-blue-400 text-sm font-semibold">{st.technique_id}</span>
                    <div className="flex gap-1 flex-wrap">
                      {st.ioc_indices.map(i => (
                        <span key={i} className="text-xs px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400">IOC #{i + 1}</span>
                      ))}
                    </div>
                    <span className="ml-auto text-xs text-slate-500">{st.ioc_count} IOCs</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── IOC RESULTS TAB ──────────────────────────────────────────────────── */}
      {activeTab === 'iocs' && (
        <div className="space-y-3">
          {normalisedIOCs.length === 0 ? (
            <p className="text-slate-500 text-sm py-8 text-center">No IOC results available.</p>
          ) : (
            normalisedIOCs.map((ioc, idx) => (
              <div key={idx} className="bg-[#0a0f1e] border border-white/[0.06] rounded-xl p-4">
                {/* Header */}
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-xs px-1.5 py-0.5 rounded bg-white/[0.06] text-slate-400 font-mono uppercase flex-shrink-0">
                    {ioc.ioc_type}
                  </span>
                  <span className="font-mono text-blue-300 text-sm font-medium truncate flex-1">
                    {ioc.ioc_value.length > 55 ? `${ioc.ioc_value.slice(0, 52)}...` : ioc.ioc_value}
                  </span>
                  {ioc.risk_level && (
                    <span className={`text-xs font-semibold flex-shrink-0 ${riskColor(ioc.risk_level)}`}>
                      {ioc.risk_score} · {ioc.risk_level}
                    </span>
                  )}
                </div>

                {ioc.context && (
                  <p className="text-xs text-slate-600 mb-3 italic">{ioc.context}</p>
                )}

                {ioc.techniques.length > 0 ? (
                  <div className="mb-3">
                    <p className="text-xs text-slate-500 font-semibold mb-2">Mapped Techniques ({ioc.techniques.length})</p>
                    <div className="space-y-1.5">
                      {ioc.techniques.map((t, ti) => (
                        <div key={ti} className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-blue-400 text-xs font-semibold">{t.id}</span>
                          {t.name && <span className="text-slate-300 text-xs">{t.name}</span>}
                          {(t.tactics ?? []).map((tac, ti2) => (
                            <span key={ti2} className="text-xs px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400">
                              {tac}
                            </span>
                          ))}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-600 mb-3">No techniques mapped.</p>
                )}

                <div className="flex items-center gap-1.5 text-xs text-slate-500 border-t border-white/[0.04] pt-2 mt-2">
                  <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
                  </svg>
                  {ioc.candidate_rules.length} detection rules generated
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* ── UNIFIED RULES TAB ────────────────────────────────────────────────── */}
      {activeTab === 'rules' && corr && (
        <div className="space-y-2">
          {(corr.unified_rules ?? []).length === 0 ? (
            <p className="text-slate-500 text-sm py-8 text-center">No rules generated for this campaign.</p>
          ) : (
            (corr.unified_rules ?? []).map((rule, i) => <RuleBlock key={rule.rule_id ?? i} rule={rule} index={i} />)
          )}
        </div>
      )}

      {/* ── APT PROJECTION TAB ───────────────────────────────────────────────── */}
      {activeTab === 'apt' && <CampaignAptProjection campaign={campaign} />}
    </div>
  );
}
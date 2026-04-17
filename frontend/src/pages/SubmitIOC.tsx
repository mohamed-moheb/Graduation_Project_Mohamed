import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';
import Sidebar from '../components/Sidebar';
import PipelineVisualization from '../components/PipelineVisualization';
import ResultsTabs from '../components/ResultsTabs';
import CampaignModal from '../components/CampaignModal';
import type { IOCSubmission, PipelineResult } from '../types';

// ── Enrichment detail panel ───────────────────────────────────────────────────
function EnrichmentPanel({ enrichment }: { enrichment: Record<string, unknown> | undefined | null }) {
  const [expanded, setExpanded] = useState(false);

  if (!enrichment || enrichment.status === 'error') {
    return (
      <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl px-5 py-3 flex items-center gap-3">
        <svg className="w-4 h-4 text-slate-600 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/>
        </svg>
        <span className="text-slate-500 text-xs">No enrichment data available for this IOC type.</span>
      </div>
    );
  }

  const riskScore   = enrichment.risk_score   as number | undefined;
  const riskLevel   = enrichment.risk_level   as string | undefined;
  const riskFactors = (enrichment.risk_factors as string[] | undefined) || [];
  const reputation  = enrichment.reputation   as Record<string, Record<string, unknown>> | undefined;
  const openPorts   = enrichment.open_ports   as number[] | undefined;
  const hostnames   = enrichment.hostnames    as string[] | undefined;
  const tags        = enrichment.tags         as string[] | undefined;
  const categories  = enrichment.categories   as string[] | undefined;
  const family      = enrichment.malwarebazaar_family as string | undefined;

  const infraFields = [
    { label: 'ASN',       value: enrichment.asn       as string | undefined },
    { label: 'Country',   value: enrichment.country   as string | undefined },
    { label: 'ISP',       value: enrichment.isp       as string | undefined },
    { label: 'SHA256',    value: enrichment.sha256    as string | undefined },
    { label: 'MD5',       value: enrichment.md5       as string | undefined },
    { label: 'Domain',    value: enrichment.domain    as string | undefined },
    { label: 'Registrar', value: enrichment.registrar as string | undefined },
  ].filter(f => f.value);

  const levelCls = (() => {
    const l = (riskLevel || '').toLowerCase();
    if (l === 'critical') return 'text-red-400';
    if (l === 'high')     return 'text-orange-400';
    if (l === 'medium')   return 'text-amber-400';
    if (l === 'low')      return 'text-green-400';
    return 'text-slate-400';
  })();

  return (
    <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl overflow-hidden fade-in">
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex items-center gap-3">
          <svg className="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7"/>
          </svg>
          <span className="text-sm font-semibold text-white">Enrichment Details</span>
          {riskScore !== undefined && (
            <span className={`text-xs font-mono ${levelCls}`}>Risk {riskScore} · {riskLevel}</span>
          )}
        </div>
        <svg className={`w-4 h-4 text-slate-500 transition-transform duration-200 ${expanded ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {expanded && (
        <div className="px-5 pb-5 space-y-4 border-t border-white/[0.06] pt-4">
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">Risk Factors</p>
            {riskFactors.length === 0 ? (
              <p className="text-slate-600 text-xs">No risk factors identified.</p>
            ) : (
              <ul className="space-y-1">
                {riskFactors.map((f, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                    <span className="text-red-400 mt-0.5 flex-shrink-0">•</span>{f}
                  </li>
                ))}
              </ul>
            )}
          </div>

          {reputation && Object.keys(reputation).length > 0 && (
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">Reputation Sources</p>
              <div className="space-y-2">
                {Object.entries(reputation).map(([source, data]) => {
                  const score = (data.score ?? data.confidence_score ?? 0) as number;
                  const ratio = data.detection_ratio as string | undefined;
                  return (
                    <div key={source} className="flex items-center gap-3">
                      <span className="text-xs text-slate-400 w-24 capitalize flex-shrink-0">{source}</span>
                      <div className="flex-1 h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                        <div className={`h-full rounded-full ${score > 70 ? 'bg-red-500' : score > 40 ? 'bg-amber-500' : 'bg-green-500'}`}
                          style={{ width: `${Math.min(100, score)}%` }} />
                      </div>
                      <span className="text-xs font-mono text-slate-300 w-10 text-right">{score}</span>
                      {ratio && <span className="text-xs text-slate-500">{ratio}</span>}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {infraFields.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">Infrastructure</p>
              <div className="grid grid-cols-2 gap-2">
                {infraFields.map(f => (
                  <div key={f.label} className="flex flex-col">
                    <span className="text-xs text-slate-600">{f.label}</span>
                    <span className="text-xs text-slate-200 font-mono truncate">{f.value}</span>
                  </div>
                ))}
                {openPorts && openPorts.length > 0 && (
                  <div className="col-span-2">
                    <span className="text-xs text-slate-600">Open Ports</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {openPorts.map(p => (
                        <span key={p} className="text-xs font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-1.5 py-0.5 rounded">{p}</span>
                      ))}
                    </div>
                  </div>
                )}
                {hostnames && hostnames.length > 0 && (
                  <div className="col-span-2">
                    <span className="text-xs text-slate-600">Hostnames</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {hostnames.map((h, i) => (
                        <span key={i} className="text-xs font-mono text-slate-300 bg-white/[0.04] border border-white/[0.06] px-1.5 py-0.5 rounded">{h}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {(tags?.length || categories?.length || family) && (
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">Classification</p>
              <div className="flex flex-wrap gap-1.5">
                {family && <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/10 border border-red-500/20 text-red-300">{family}</span>}
                {categories?.map((c, i) => <span key={i} className="text-xs px-2 py-0.5 rounded-full bg-orange-500/10 border border-orange-500/20 text-orange-300">{c}</span>)}
                {tags?.map((t, i) => <span key={i} className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-300">{t}</span>)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
const IOC_TYPES = [
  { value: 'ip',              label: 'IP Address' },
  { value: 'domain',          label: 'Domain' },
  { value: 'url',             label: 'URL' },
  { value: 'file_hash',       label: 'File Hash' },
  { value: 'email',           label: 'Email Address' },
  { value: 'process_command', label: 'Process Command' },
  { value: 'registry_key',    label: 'Registry Key' },
];

function generateRuleHash(iocValue: string): string {
  let hash = 0;
  const str = `rule_${iocValue}_${Date.now()}`;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}

function formatDate(dt: string) {
  return new Date(dt).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

interface CheckResponse {
  exists: boolean;
  own: boolean;
  submission: IOCSubmission | null;
}

export default function SubmitIOC() {
  const navigate = useNavigate();

  const [iocType,        setIocType]        = useState('ip');
  const [iocValue,       setIocValue]       = useState('');
  const [context,        setContext]        = useState('');
  const [contextTouched, setContextTouched] = useState(false);
  const [submitting,     setSubmitting]     = useState(false);
  const [error,          setError]          = useState('');

  // Campaign modal
  const [showCampaign, setShowCampaign] = useState(false);

  // Pipeline
  const [showPipeline, setShowPipeline] = useState(false);
  const [submittedIOC, setSubmittedIOC] = useState<{ type: string; value: string; context: string } | null>(null);

  // Duplicate
  const [duplicate,        setDuplicate]        = useState<IOCSubmission | null>(null);
  const [duplicateResults, setDuplicateResults] = useState<PipelineResult | null>(null);
  const [duplicateIsOwn,   setDuplicateIsOwn]   = useState(false);
  const [allowResubmit,    setAllowResubmit]    = useState(false);

  // Results
  const [finalResults,      setFinalResults]      = useState<PipelineResult | null>(null);
  const [resultsKey,        setResultsKey]        = useState(0);
  const [saved,             setSaved]             = useState(false);
  const [savedSubmissionId, setSavedSubmissionId] = useState<number | null>(null);

  const contextMissing         = contextTouched && !context.trim();
  const resubmitContextMissing = allowResubmit && contextTouched && !context.trim();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setContextTouched(true);
    if (!iocValue.trim() || !context.trim()) return;

    setError('');
    setDuplicate(null);
    setDuplicateResults(null);
    setDuplicateIsOwn(false);
    setFinalResults(null);
    setSaved(false);
    setSavedSubmissionId(null);
    setShowPipeline(false);
    setSubmittedIOC(null);
    setSubmitting(true);

    if (allowResubmit) {
      setAllowResubmit(false);
      setSubmittedIOC({ type: iocType, value: iocValue.trim(), context: context.trim() });
      setResultsKey(k => k + 1);
      setShowPipeline(true);
      setSubmitting(false);
      return;
    }

    try {
      const checkRes = await api.post<CheckResponse>(
        '/submissions/check',
        { ioc_value: iocValue.trim() }
      );

      if (checkRes.data.exists && checkRes.data.submission) {
        const sub   = checkRes.data.submission;
        const isOwn = checkRes.data.own ?? false;
        setDuplicate(sub);
        setDuplicateIsOwn(isOwn);
        setSavedSubmissionId(sub.id);
        if (sub.result_json) {
          try { setDuplicateResults(JSON.parse(sub.result_json)); }
          catch { setDuplicateResults({} as PipelineResult); }
        }
        setSubmitting(false);
        return;
      }

      setSubmittedIOC({ type: iocType, value: iocValue.trim(), context: context.trim() });
      setResultsKey(k => k + 1);
      setShowPipeline(true);
      setSubmitting(false);
    } catch {
      setError('Failed to check IOC. Please try again.');
      setSubmitting(false);
    }
  };

  const handlePipelineComplete = async (results: PipelineResult) => {
    setFinalResults(results);
    try {
      const saveRes = await api.post<{ id: number }>('/submissions/save', {
        ioc_type:    iocType,
        ioc_value:   iocValue.trim(),
        context:     context.trim() || null,
        result_json: JSON.stringify(results),
        rule_hash:   generateRuleHash(iocValue),
      });
      setSaved(true);
      setSavedSubmissionId(saveRes.data.id);
    } catch {
      // silent
    }
  };

  const handleAllowResubmit = () => {
    setAllowResubmit(true);
    setDuplicate(null);
    setDuplicateResults(null);
    setContext('');
    setContextTouched(false);
  };

  const resetForm = () => {
    setIocValue('');
    setContext('');
    setContextTouched(false);
    setIocType('ip');
    setShowPipeline(false);
    setSubmittedIOC(null);
    setDuplicate(null);
    setDuplicateResults(null);
    setDuplicateIsOwn(false);
    setAllowResubmit(false);
    setFinalResults(null);
    setSaved(false);
    setSavedSubmissionId(null);
    setError('');
    setSubmitting(false);
  };

  return (
    <div className="flex h-screen bg-[#080d1a] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">

        {/* Header */}
        <div className="border-b border-white/[0.06] px-8 py-5 flex items-center gap-4">
          <button onClick={() => navigate('/analyst')} className="text-slate-500 hover:text-white transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
          </button>
          <div className="flex-1">
            <h2 className="text-xl font-semibold text-white">Submit IOC</h2>
            <p className="text-sm text-slate-500 mt-0.5">Analyze indicators of compromise through the ATT&CK pipeline</p>
          </div>
          {/* Campaign button in header */}
          <button
            onClick={() => setShowCampaign(true)}
            className="flex items-center gap-2 text-sm px-4 py-2 rounded-lg bg-purple-600/15 border border-purple-500/25 text-purple-300 hover:bg-purple-600/25 transition-all"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
            </svg>
            New Campaign
          </button>
        </div>

        <div className="px-8 py-6">
          <div className="max-w-3xl mx-auto space-y-6">

            {/* Form */}
            <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-6">
              <h3 className="text-sm font-semibold text-white mb-5 flex items-center gap-2">
                <svg className="w-4 h-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                IOC Details
                {allowResubmit && (
                  <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400">
                    New analysis — enter different context
                  </span>
                )}
              </h3>

              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">IOC Type</label>
                    <select value={iocType} onChange={e => setIocType(e.target.value)}
                      disabled={showPipeline}
                      className="w-full bg-[#080d1a] border border-white/[0.1] rounded-lg px-4 py-3 text-white text-sm focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/20 transition-all disabled:opacity-50 appearance-none cursor-pointer">
                      {IOC_TYPES.map(t => <option key={t.value} value={t.value} className="bg-[#080d1a]">{t.label}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">IOC Value</label>
                    <input type="text" value={iocValue} onChange={e => setIocValue(e.target.value)}
                      disabled={showPipeline || allowResubmit}
                      className="w-full bg-[#080d1a] border border-white/[0.1] rounded-lg px-4 py-3 text-white text-sm placeholder-slate-700 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/20 transition-all disabled:opacity-50 font-mono"
                      placeholder="e.g. 192.168.1.1" required />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                    Context <span className="text-red-400 normal-case font-semibold">*</span>
                    {allowResubmit && (
                      <span className="text-blue-400 ml-2 normal-case font-normal">— must differ from previous submission</span>
                    )}
                  </label>
                  <textarea
                    value={context}
                    onChange={e => setContext(e.target.value)}
                    onBlur={() => setContextTouched(true)}
                    disabled={showPipeline}
                    rows={3}
                    className={`w-full bg-[#080d1a] border rounded-lg px-4 py-3 text-white text-sm placeholder-slate-700 focus:outline-none focus:ring-1 transition-all resize-none disabled:opacity-50 ${
                      (contextMissing || resubmitContextMissing)
                        ? 'border-red-500/50 focus:border-red-500/60 focus:ring-red-500/20'
                        : 'border-white/[0.1] focus:border-blue-500/60 focus:ring-blue-500/20'
                    }`}
                    placeholder={allowResubmit
                      ? "Describe your specific investigation context that differs from the previous analysis..."
                      : "Describe where this IOC was found, investigation context, threat intel source..."
                    }
                  />
                  {(contextMissing || resubmitContextMissing) && (
                    <p className="text-red-400 text-xs mt-1 flex items-center gap-1">
                      <svg className="w-3 h-3 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/></svg>
                      Context is required for accurate analysis.
                    </p>
                  )}
                </div>

                {error && (
                  <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm px-4 py-3 rounded-lg flex items-center gap-2">
                    <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/></svg>
                    {error}
                  </div>
                )}

                {!showPipeline && !duplicate && (
                  <div className="flex items-center gap-3 pt-1 flex-wrap">
                    <button type="submit"
                      disabled={submitting || !iocValue.trim() || !context.trim()}
                      className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold px-6 py-3 rounded-lg transition-all duration-200 text-sm">
                      {submitting ? (
                        <><svg className="w-4 h-4 spin" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M21 12a9 9 0 11-6.219-8.56"/></svg>Checking...</>
                      ) : (
                        <><svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                        {allowResubmit ? 'Run New Analysis' : 'Analyze IOC'}</>
                      )}
                    </button>

                    {/* Campaign button inside form */}
                    {!allowResubmit && (
                      <button
                        type="button"
                        onClick={() => setShowCampaign(true)}
                        className="flex items-center gap-2 text-sm px-4 py-3 rounded-lg bg-purple-600/15 border border-purple-500/25 text-purple-300 hover:bg-purple-600/25 transition-all"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                        </svg>
                        Campaign
                      </button>
                    )}

                    {allowResubmit ? (
                      <button type="button" onClick={resetForm} className="text-sm text-slate-500 hover:text-slate-300 transition-colors">
                        Cancel
                      </button>
                    ) : (
                      <button type="button" onClick={resetForm} className="text-sm text-slate-500 hover:text-slate-300 transition-colors">
                        Clear
                      </button>
                    )}
                  </div>
                )}

                {(showPipeline || duplicate) && (
                  <button type="button" onClick={resetForm} className="text-sm text-slate-500 hover:text-slate-300 transition-colors underline">
                    Submit another IOC
                  </button>
                )}
              </form>
            </div>

            {/* ── Duplicate banner ─────────────────────────────────────────── */}
            {duplicate && !allowResubmit && (
              <div className="fade-in space-y-4">
                {duplicateIsOwn ? (
                  <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl px-5 py-4 flex items-start gap-3">
                    <svg className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <div>
                      <p className="text-blue-300 font-semibold text-sm">Already Analyzed by You</p>
                      <p className="text-slate-400 text-sm mt-0.5">
                        You submitted this IOC on{' '}
                        <span className="text-white font-medium">{formatDate(duplicate.submitted_at)}</span>.
                        Showing your cached results below.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl px-5 py-4">
                    <div className="flex items-start gap-3">
                      <svg className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path d="M13 10V3L4 14h7v7l9-11h-7z"/>
                      </svg>
                      <div className="flex-1 min-w-0">
                        <p className="text-amber-300 font-semibold text-sm">
                          Previously Analyzed by <span className="text-white">{duplicate.submitted_by}</span>
                        </p>
                        <p className="text-slate-400 text-sm mt-0.5">
                          Submitted on{' '}
                          <span className="text-white font-medium">{formatDate(duplicate.submitted_at)}</span>.
                          Showing their cached results below.
                        </p>
                        {duplicate.context && (
                          <div className="mt-3 bg-white/[0.03] border border-white/[0.06] rounded-lg px-3 py-2.5">
                            <p className="text-xs text-slate-500 uppercase font-semibold tracking-wider mb-1">Their context</p>
                            <p className="text-slate-300 text-xs leading-relaxed">{duplicate.context}</p>
                          </div>
                        )}
                        <div className="flex items-center gap-3 mt-4">
                          <button
                            onClick={handleAllowResubmit}
                            className="flex items-center gap-2 text-sm px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium transition-colors"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4"/>
                            </svg>
                            Submit with Different Context
                          </button>
                          <span className="text-xs text-slate-600">or view cached results below</span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {duplicateResults ? (
                  <>
                    <EnrichmentPanel enrichment={(duplicateResults as Record<string, unknown>).enrichment as Record<string, unknown> | undefined} />
                    <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-5">
                      <ResultsTabs
                        key={`dup-${duplicate.id}`}
                        results={duplicateResults}
                        iocType={iocType}
                        iocValue={iocValue.trim()}
                        context={duplicate.context || context.trim()}
                        submissionId={duplicate.id}
                      />
                    </div>
                  </>
                ) : (
                  <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-5 text-center text-slate-500 text-sm">
                    No detailed results available for this cached submission.
                  </div>
                )}
              </div>
            )}

            {/* Pipeline */}
            {showPipeline && submittedIOC && (
              <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-6 fade-in">
                <h3 className="text-sm font-semibold text-white mb-5 flex items-center gap-2">
                  <svg className="w-4 h-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18"/>
                  </svg>
                  Analysis Pipeline
                  {saved && (
                    <span className="ml-auto inline-flex items-center gap-1 text-xs text-green-400 bg-green-500/10 border border-green-500/20 px-2 py-0.5 rounded-full">
                      <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path d="M5 13l4 4L19 7"/></svg>
                      Saved
                    </span>
                  )}
                </h3>
                <PipelineVisualization
                  iocType={submittedIOC.type}
                  iocValue={submittedIOC.value}
                  context={submittedIOC.context}
                  onComplete={handlePipelineComplete}
                />
              </div>
            )}

            {/* Results */}
            {finalResults && (
              <>
                <EnrichmentPanel enrichment={finalResults.enrichment as Record<string, unknown> | undefined | null} />
                <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-5 fade-in">
                  <ResultsTabs
                    key={`result-${resultsKey}`}
                    results={finalResults}
                    iocType={submittedIOC?.type}
                    iocValue={submittedIOC?.value}
                    context={submittedIOC?.context}
                    submissionId={savedSubmissionId ?? undefined}
                  />
                </div>
              </>
            )}

          </div>
        </div>
      </main>

      {/* Campaign modal */}
      {showCampaign && (
        <CampaignModal onClose={() => setShowCampaign(false)} />
      )}
    </div>
  );
}
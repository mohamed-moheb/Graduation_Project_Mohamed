import { useState } from 'react';
import api from '../api/client';
import type { CampaignIOCItem, Campaign } from '../types';
import CampaignResults from './CampaignResults';

const IOC_TYPES = [
  { value: 'ip',              label: 'IP Address' },
  { value: 'domain',          label: 'Domain' },
  { value: 'url',             label: 'URL' },
  { value: 'file_hash',       label: 'File Hash' },
  { value: 'email',           label: 'Email' },
  { value: 'process_command', label: 'Process Command' },
  { value: 'registry_key',    label: 'Registry Key' },
];

const emptyIOC = (): CampaignIOCItem => ({ ioc_type: 'ip', ioc_value: '', context: '' });

interface Props {
  onClose: () => void;
}

export default function CampaignModal({ onClose }: Props) {
  const [name,        setName]        = useState('');
  const [description, setDescription] = useState('');
  const [iocs,        setIocs]        = useState<CampaignIOCItem[]>([emptyIOC()]);
  const [submitting,  setSubmitting]  = useState(false);
  const [error,       setError]       = useState('');
  const [result,      setResult]      = useState<Campaign | null>(null);

  const updateIOC = (idx: number, field: keyof CampaignIOCItem, value: string) => {
    setIocs(prev => prev.map((ioc, i) => i === idx ? { ...ioc, [field]: value } : ioc));
  };

  const addIOC = () => {
    if (iocs.length >= 50) return;
    setIocs(prev => [...prev, emptyIOC()]);
  };

  const removeIOC = (idx: number) => {
    if (iocs.length === 1) return;
    setIocs(prev => prev.filter((_, i) => i !== idx));
  };

  const duplicateIOC = (idx: number) => {
    setIocs(prev => [
      ...prev.slice(0, idx + 1),
      { ...prev[idx] },
      ...prev.slice(idx + 1),
    ]);
  };

  const handleSubmit = async () => {
    if (!name.trim()) { setError('Campaign name is required.'); return; }
    const validIocs = iocs.filter(i => i.ioc_value.trim());
    if (!validIocs.length) { setError('At least one IOC value is required.'); return; }

    setError('');
    setSubmitting(true);
    try {
      const res = await api.post<Campaign>('/api/campaign/submit', {
        name:        name.trim(),
        description: description.trim(),
        iocs:        validIocs,
      });
      setResult(res.data);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })
        ?.response?.data?.detail;
      setError(msg || 'Campaign submission failed.');
    } finally {
      setSubmitting(false);
    }
  };

  // ── Result view ─────────────────────────────────────────────────────────────
  if (result) {
    return (
      <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 backdrop-blur-sm overflow-y-auto py-8 px-4">
        <div className="w-full max-w-5xl bg-[#0d1525] border border-white/[0.08] rounded-2xl shadow-2xl">
          <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.06]">
            <div>
              <h2 className="text-white font-bold text-lg">
                {result.campaign_name ?? result.name}
              </h2>
              <p className="text-slate-500 text-xs mt-0.5">
                Campaign #{result.campaign_id} · {result.analyzed_count ?? result.ioc_count} IOCs analyzed
              </p>
            </div>
            <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors p-1">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div className="p-6">
            <CampaignResults campaign={result} />
          </div>
        </div>
      </div>
    );
  }

  // ── Form view ───────────────────────────────────────────────────────────────
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 backdrop-blur-sm overflow-y-auto py-8 px-4">
      <div className="w-full max-w-3xl bg-[#0d1525] border border-white/[0.08] rounded-2xl shadow-2xl">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.06]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-purple-600/20 border border-purple-500/30 flex items-center justify-center">
              <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
              </svg>
            </div>
            <div>
              <h2 className="text-white font-bold text-base">New Campaign</h2>
              <p className="text-slate-500 text-xs">Submit multiple IOCs for correlated analysis</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors p-1">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="px-6 py-5 space-y-5 max-h-[80vh] overflow-y-auto">

          {/* Campaign meta */}
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Campaign Name <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. Breach WS-042 April 2026"
                className="w-full bg-[#080d1a] border border-white/[0.1] rounded-lg px-4 py-2.5 text-white text-sm placeholder-slate-700 focus:outline-none focus:border-purple-500/60 focus:ring-1 focus:ring-purple-500/20 transition-all"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Description
              </label>
              <textarea
                value={description}
                onChange={e => setDescription(e.target.value)}
                rows={2}
                placeholder="Brief description of the investigation or incident..."
                className="w-full bg-[#080d1a] border border-white/[0.1] rounded-lg px-4 py-2.5 text-white text-sm placeholder-slate-700 focus:outline-none focus:border-purple-500/60 focus:ring-1 focus:ring-purple-500/20 transition-all resize-none"
              />
            </div>
          </div>

          {/* IOC list */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                IOCs <span className="text-slate-600 normal-case font-normal">({iocs.length}/50)</span>
              </label>
            </div>

            <div className="space-y-3">
              {iocs.map((ioc, idx) => (
                <div key={idx} className="bg-[#0a0f1e] border border-white/[0.06] rounded-xl p-4">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
                      IOC #{idx + 1}
                    </span>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => duplicateIOC(idx)}
                        title="Duplicate"
                        className="text-xs px-2 py-1 rounded text-slate-500 hover:text-blue-400 hover:bg-blue-500/10 transition-colors"
                      >
                        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <rect x="9" y="9" width="13" height="13" rx="2"/>
                          <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
                        </svg>
                      </button>
                      {iocs.length > 1 && (
                        <button
                          onClick={() => removeIOC(idx)}
                          title="Remove"
                          className="text-xs px-2 py-1 rounded text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                        >
                          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12"/>
                          </svg>
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 mb-3">
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">Type</label>
                      <select
                        value={ioc.ioc_type}
                        onChange={e => updateIOC(idx, 'ioc_type', e.target.value)}
                        className="w-full bg-[#080d1a] border border-white/[0.08] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-purple-500/50 transition-all appearance-none"
                      >
                        {IOC_TYPES.map(t => (
                          <option key={t.value} value={t.value} className="bg-[#080d1a]">{t.label}</option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs text-slate-500 mb-1">Value</label>
                      <input
                        type="text"
                        value={ioc.ioc_value}
                        onChange={e => updateIOC(idx, 'ioc_value', e.target.value)}
                        placeholder="e.g. 185.220.101.1"
                        className="w-full bg-[#080d1a] border border-white/[0.08] rounded-lg px-3 py-2 text-white text-sm font-mono placeholder-slate-700 focus:outline-none focus:border-purple-500/50 transition-all"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs text-slate-500 mb-1">Context</label>
                    <textarea
                      value={ioc.context}
                      onChange={e => updateIOC(idx, 'context', e.target.value)}
                      rows={2}
                      placeholder="Where was this IOC found? What was the context?"
                      className="w-full bg-[#080d1a] border border-white/[0.08] rounded-lg px-3 py-2 text-white text-sm placeholder-slate-700 focus:outline-none focus:border-purple-500/50 transition-all resize-none"
                    />
                  </div>
                </div>
              ))}
            </div>

            <button
              onClick={addIOC}
              disabled={iocs.length >= 50}
              className="mt-3 w-full flex items-center justify-center gap-2 py-2.5 rounded-xl border border-dashed border-white/[0.1] text-slate-500 hover:text-white hover:border-white/[0.2] hover:bg-white/[0.02] transition-all text-sm disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path d="M12 5v14M5 12h14" />
              </svg>
              Add IOC
            </button>
          </div>

          {error && (
            <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm px-4 py-3 rounded-lg flex items-center gap-2">
              <svg className="w-4 h-4 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/>
              </svg>
              {error}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-white/[0.06] flex items-center justify-between gap-3">
          <span className="text-xs text-slate-600">
            {iocs.filter(i => i.ioc_value.trim()).length} of {iocs.length} IOCs filled
          </span>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="text-sm text-slate-400 hover:text-white transition-colors px-4 py-2"
            >
              Cancel
            </button>
            <button
              onClick={handleSubmit}
              disabled={submitting || !name.trim() || !iocs.some(i => i.ioc_value.trim())}
              className="flex items-center gap-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold px-5 py-2.5 rounded-lg transition-all text-sm"
            >
              {submitting ? (
                <>
                  <svg className="w-4 h-4 spin" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path d="M21 12a9 9 0 11-6.219-8.56"/>
                  </svg>
                  Analyzing {iocs.filter(i => i.ioc_value.trim()).length} IOCs...
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path d="M13 10V3L4 14h7v7l9-11h-7z"/>
                  </svg>
                  Run Campaign Analysis
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
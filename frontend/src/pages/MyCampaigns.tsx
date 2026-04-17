import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client';
import Sidebar from '../components/Sidebar';
import CampaignResults from '../components/CampaignResults';
import type { Campaign } from '../types';

function formatDate(dt: string) {
  return new Date(dt).toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function riskColor(level?: string | null) {
  const l = (level || '').toLowerCase();
  if (l === 'critical') return 'text-red-400';
  if (l === 'high')     return 'text-orange-400';
  if (l === 'medium')   return 'text-amber-400';
  if (l === 'low')      return 'text-green-400';
  return 'text-slate-400';
}

export default function MyCampaigns() {
  const navigate = useNavigate();
  const [campaigns,     setCampaigns]     = useState<Campaign[]>([]);
  const [loading,       setLoading]       = useState(true);
  const [selected,      setSelected]      = useState<Campaign | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailError,   setDetailError]   = useState<string | null>(null);

  useEffect(() => {
    api.get<Campaign[]>('/api/campaigns/mine')
      .then(res => setCampaigns(res.data))
      .catch(() => setCampaigns([]))
      .finally(() => setLoading(false));
  }, []);

  const openCampaign = async (id: number) => {
    if (loadingDetail) return;
    setDetailError(null);
    setLoadingDetail(true);
    try {
      const res = await api.get<Campaign>(`/api/campaign/${id}`);
      setSelected(res.data);
    } catch (err: unknown) {
      const msg    = (err as { response?: { data?: { detail?: string }; status?: number } })?.response?.data?.detail;
      const status = (err as { response?: { status?: number } })?.response?.status;
      setDetailError(`Failed to load campaign (${status ?? 'network error'}): ${msg ?? 'check console'}`);
      console.error('Campaign load error:', err);
    } finally {
      setLoadingDetail(false);
    }
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
          <div>
            <h2 className="text-xl font-semibold text-white">My Campaigns</h2>
            <p className="text-sm text-slate-500 mt-0.5">Multi-IOC correlated analysis campaigns</p>
          </div>
        </div>

        <div className="px-8 py-6">
          {detailError && (
            <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm px-4 py-3 rounded-lg mb-4">
              {detailError}
            </div>
          )}

          {loading ? (
            <div className="py-20 flex items-center justify-center">
              <svg className="w-6 h-6 spin text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
              </svg>
            </div>
          ) : campaigns.length === 0 ? (
            <div className="py-20 text-center">
              <p className="text-slate-600 text-sm">No campaigns yet.</p>
              <p className="text-slate-700 text-xs mt-1">Use the "Campaign" button on the Submit IOC page to create one.</p>
              <button
                onClick={() => navigate('/analyst/submit')}
                className="mt-4 text-sm px-4 py-2 rounded-lg bg-purple-600/15 border border-purple-500/25 text-purple-300 hover:bg-purple-600/25 transition-all"
              >
                Go to Submit IOC
              </button>
            </div>
          ) : (
            <div className="space-y-3 max-w-4xl">
              {campaigns.map(c => (
                <div
                  key={c.campaign_id}
                  onClick={() => openCampaign(c.campaign_id)}
                  className="w-full bg-[#0f1629] border border-white/[0.07] rounded-xl px-5 py-4 hover:border-purple-500/30 hover:bg-purple-500/5 transition-all text-left cursor-pointer"
                >
                  <div className="flex items-center gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-1">
                        <span className="text-white font-semibold text-sm truncate">{c.name}</span>
                        <span className={`text-xs px-1.5 py-0.5 rounded-full border flex-shrink-0 ${
                          c.status === 'complete'
                            ? 'bg-green-500/10 border-green-500/20 text-green-400'
                            : 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                        }`}>
                          {c.status}
                        </span>
                      </div>
                      {c.description && (
                        <p className="text-xs text-slate-500 truncate">{c.description}</p>
                      )}
                      <p className="text-xs text-slate-600 mt-1">{formatDate(c.created_at)}</p>
                    </div>
                    <div className="flex items-center gap-4 flex-shrink-0 text-center">
                      <div>
                        <div className="text-xs text-slate-500">IOCs</div>
                        <div className="text-sm font-bold text-white">{c.ioc_count}</div>
                      </div>
                      {c.combined_risk_score !== undefined && c.combined_risk_score !== null && (
                        <div>
                          <div className="text-xs text-slate-500">Risk</div>
                          <div className={`text-sm font-bold ${riskColor(c.combined_risk_level)}`}>{c.combined_risk_score}</div>
                        </div>
                      )}
                      {c.unified_rule_count !== undefined && c.unified_rule_count !== null && (
                        <div>
                          <div className="text-xs text-slate-500">Rules</div>
                          <div className="text-sm font-bold text-white">{c.unified_rule_count}</div>
                        </div>
                      )}
                      {c.top_apt && (
                        <div>
                          <div className="text-xs text-slate-500">Top APT</div>
                          <div className="text-xs font-semibold text-red-300 max-w-[80px] truncate">{c.top_apt}</div>
                        </div>
                      )}
                      {loadingDetail ? (
                        <svg className="w-4 h-4 spin text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path d="M21 12a9 9 0 11-6.219-8.56"/>
                        </svg>
                      ) : (
                        <svg className="w-4 h-4 text-slate-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7"/>
                        </svg>
                      )}
                    </div>
                  </div>
                  {/* FIX: gap_tactics detection gaps block removed */}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Detail modal */}
        {selected && (
          <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 backdrop-blur-sm overflow-y-auto py-8 px-4">
            <div className="w-full max-w-5xl bg-[#0d1525] border border-white/[0.08] rounded-2xl shadow-2xl">
              <div className="flex items-center justify-between px-6 py-4 border-b border-white/[0.06]">
                <div>
                  <h2 className="text-white font-bold text-lg">{selected.name}</h2>
                  <p className="text-slate-500 text-xs mt-0.5">
                    Campaign #{selected.campaign_id} · {formatDate(selected.created_at)}
                  </p>
                </div>
                <button
                  onClick={() => setSelected(null)}
                  className="text-slate-500 hover:text-white transition-colors p-1"
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
              <div className="p-6">
                <CampaignResults campaign={selected} />
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
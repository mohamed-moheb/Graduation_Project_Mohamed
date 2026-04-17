import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts';
import api from '../api/client';
import Sidebar from '../components/Sidebar';
import StatCard from '../components/StatCard';
import { useAuth } from '../contexts/AuthContext';
import type { Stats, IOCSubmission, Campaign } from '../types';

const IOC_TYPE_LABELS: Record<string, string> = {
  ip: 'IP Address', domain: 'Domain', url: 'URL', file_hash: 'File Hash',
  email: 'Email', process_command: 'Process', registry_key: 'Registry',
};

const IOC_TYPE_COLORS: Record<string, string> = {
  ip: '#3b82f6', domain: '#22c55e', url: '#f59e0b', file_hash: '#ef4444',
  email: '#8b5cf6', process_command: '#06b6d4', registry_key: '#ec4899',
};

function riskColor(level?: string | null) {
  const l = (level || '').toLowerCase();
  if (l === 'critical') return 'text-red-400';
  if (l === 'high')     return 'text-orange-400';
  if (l === 'medium')   return 'text-amber-400';
  if (l === 'low')      return 'text-green-400';
  return 'text-slate-400';
}

function StatusBadge({ hasResult }: { hasResult: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
      hasResult
        ? 'bg-green-500/10 text-green-400 border border-green-500/20'
        : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
    }`}>
      <span className={`w-1.5 h-1.5 rounded-full ${hasResult ? 'bg-green-400' : 'bg-amber-400'}`} />
      {hasResult ? 'Analyzed' : 'Pending'}
    </span>
  );
}

function RiskBadge({ level }: { level?: string }) {
  if (!level || level === 'Unknown') return <span className="text-slate-600 text-xs">—</span>;
  const styles: Record<string, string> = {
    Critical: 'bg-red-500/10 border-red-500/20 text-red-400',
    High:     'bg-orange-500/10 border-orange-500/20 text-orange-400',
    Medium:   'bg-amber-500/10 border-amber-500/20 text-amber-400',
    Low:      'bg-green-500/10 border-green-500/20 text-green-400',
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${styles[level] ?? 'bg-slate-500/10 border-slate-500/20 text-slate-400'}`}>
      {level}
    </span>
  );
}

interface ParsedResult {
  techCount: number;
  firstTechId: string;
  riskLevel?: string;
  riskScore?: number;
}

function parseResult(resultJson: string | null): ParsedResult {
  if (!resultJson) return { techCount: 0, firstTechId: '—' };
  try {
    const data = JSON.parse(resultJson);
    const techs: unknown[] = data.techniques || [];
    const firstTech = techs[0];
    const firstTechId =
      typeof firstTech === 'string' ? firstTech.split(' ')[0]
      : typeof firstTech === 'object' && firstTech !== null && 'id' in firstTech
        ? String((firstTech as { id: unknown }).id)
        : '—';
    return { techCount: techs.length, firstTechId: firstTechId || '—', riskLevel: data.risk_level, riskScore: data.risk_score };
  } catch {
    return { techCount: 0, firstTechId: '—' };
  }
}

function formatDate(dt: string) {
  return new Date(dt).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: { value: number }[]; label?: string }) => {
  if (active && payload?.length) {
    return (
      <div className="bg-[#0f1629] border border-white/[0.1] rounded-lg px-3 py-2 text-xs shadow-xl">
        <p className="text-slate-400">{label}</p>
        <p className="text-blue-400 font-semibold">{payload[0].value} IOC{payload[0].value !== 1 ? 's' : ''}</p>
      </div>
    );
  }
  return null;
};

export default function AnalystDashboard() {
  const { user } = useAuth();
  const navigate  = useNavigate();

  const [stats,       setStats]       = useState<Stats | null>(null);
  const [submissions, setSubmissions] = useState<IOCSubmission[]>([]);
  const [campaigns,   setCampaigns]   = useState<Campaign[]>([]);
  const [loading,     setLoading]     = useState(true);

  useEffect(() => {
    Promise.all([
      api.get<Stats>('/submissions/stats'),
      api.get<IOCSubmission[]>('/submissions/mine'),
      api.get<Campaign[]>('/api/campaigns/mine'),
    ]).then(([statsRes, subsRes, campRes]) => {
      setStats(statsRes.data);
      setSubmissions(subsRes.data);
      setCampaigns(campRes.data);
    }).finally(() => setLoading(false));
  }, []);

  const topTechniques = useMemo(() => {
    const counts = new Map<string, number>();
    // Single IOC submissions
    for (const sub of submissions) {
      if (!sub.result_json) continue;
      try {
        const data = JSON.parse(sub.result_json);
        for (const t of (data.techniques || []) as unknown[]) {
          const id = typeof t === 'string' ? t.split(' ')[0] : String((t as { id?: unknown }).id || '');
          if (id && id !== 'undefined') counts.set(id, (counts.get(id) || 0) + 1);
        }
      } catch { /* skip */ }
    }
    // Campaign IOC techniques
    for (const c of campaigns) {
      const techs = (c.correlation?.shared_techniques ?? []);
      for (const st of techs) {
        counts.set(st.technique_id, (counts.get(st.technique_id) || 0) + st.ioc_count);
      }
    }
    return Array.from(counts.entries()).map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count).slice(0, 5);
  }, [submissions, campaigns]);

  const riskDistribution = useMemo(() => {
    const levels = ['Critical', 'High', 'Medium', 'Low', 'Clean'];
    const counts: Record<string, number> = Object.fromEntries(levels.map(l => [l, 0]));
    let other = 0;
    for (const sub of submissions) {
      if (!sub.result_json) { other++; continue; }
      try {
        const level: string = JSON.parse(sub.result_json).risk_level || '';
        if (levels.includes(level)) counts[level]++; else other++;
      } catch { other++; }
    }
    // Include campaign combined risk levels
    for (const c of campaigns) {
      const level = c.combined_risk_level || '';
      if (levels.includes(level)) counts[level]++; else if (level) other++;
    }
    return { counts, other, total: submissions.length + campaigns.length };
  }, [submissions, campaigns]);

  const mostActiveIocType = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const sub of submissions) counts[sub.ioc_type] = (counts[sub.ioc_type] || 0) + 1;
    for (const c of campaigns) {
      for (const ioc of (c.ioc_results || [])) {
        if (ioc.ioc_type) counts[ioc.ioc_type] = (counts[ioc.ioc_type] || 0) + 1;
      }
    }
    if (!Object.keys(counts).length) return null;
    const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
    return top ? { type: top[0], count: top[1] } : null;
  }, [submissions, campaigns]);

  const iocTypeData = useMemo(() => {
    // Start with stats counts (single IOC submissions)
    const counts: Record<string, number> = {};
    for (const tc of (stats?.ioc_type_counts || [])) counts[tc.ioc_type] = tc.count;
    // Add campaign IOC types
    for (const c of campaigns) {
      for (const ioc of (c.ioc_results || [])) {
        if (ioc.ioc_type) counts[ioc.ioc_type] = (counts[ioc.ioc_type] || 0) + 1;
      }
    }
    return Object.entries(counts).map(([ioc_type, count]) => ({
      name:  IOC_TYPE_LABELS[ioc_type] || ioc_type,
      count,
      fill:  IOC_TYPE_COLORS[ioc_type] || '#64748b',
    }));
  }, [stats, campaigns]);

  if (loading) {
    return (
      <div className="flex h-screen bg-[#080d1a]">
        <Sidebar />
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center">
            <svg className="w-8 h-8 spin text-blue-500 mx-auto mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path d="M21 12a9 9 0 11-6.219-8.56" />
            </svg>
            <p className="text-slate-500 text-sm">Loading dashboard...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-[#080d1a] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto relative">

        {/* Header */}
        <div className="border-b border-white/[0.06] px-8 py-5">
          <h2 className="text-xl font-semibold text-white">
            Welcome back, <span className="text-blue-400">{user?.username}</span>
          </h2>
          <p className="text-sm text-slate-500 mt-0.5">Your personal threat intelligence workspace</p>
        </div>

        <div className="px-8 py-6 space-y-6">

          {/* Stat cards — now 4 including Campaigns */}
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
            <StatCard label="My IOCs" value={submissions.length} color="blue"
              icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>}
              subtitle="IOCs submitted by you" />
            <StatCard label="Campaigns" value={stats?.total_campaigns ?? campaigns.length} color="purple"
              icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>}
              subtitle="Multi-IOC investigations" />
            <StatCard label="Rules Generated" value={stats?.rules_generated ?? 0} color="green"
              icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>}
              subtitle="Detection rules from your IOCs" />
            <StatCard label="APTs Detected" value={stats?.apts_detected ?? 0} color="red"
              icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /></svg>}
              subtitle="Threat actor attributions" />
          </div>

          {/* Intelligence Summary + Chart row */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {/* Threat Intelligence Summary */}
            <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-5 space-y-5">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <svg className="w-4 h-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                Threat Intelligence Summary
              </h3>

              {/* Top techniques */}
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">Top Techniques</p>
                {topTechniques.length === 0 ? (
                  <p className="text-slate-600 text-xs">No technique data yet.</p>
                ) : (
                  <div className="space-y-1.5">
                    {topTechniques.map((t, i) => (
                      <div key={t.id} className="flex items-center gap-3">
                        <span className="text-xs text-slate-600 w-4 text-right flex-shrink-0">{i + 1}.</span>
                        <span className="font-mono text-blue-400 text-xs w-20 flex-shrink-0">{t.id}</span>
                        <div className="flex-1 h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                          <div className="h-full bg-blue-500/60 rounded-full"
                            style={{ width: `${Math.round((t.count / (topTechniques[0]?.count || 1)) * 100)}%` }} />
                        </div>
                        <span className="text-xs text-slate-500 w-6 text-right flex-shrink-0">×{t.count}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Risk distribution */}
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">Risk Distribution</p>
                {riskDistribution.total === 0 ? (
                  <p className="text-slate-600 text-xs">No data yet.</p>
                ) : (
                  <>
                    <div className="flex h-3 rounded-full overflow-hidden gap-px">
                      {[
                        { key: 'Critical', color: 'bg-red-500' },
                        { key: 'High',     color: 'bg-orange-500' },
                        { key: 'Medium',   color: 'bg-amber-500' },
                        { key: 'Low',      color: 'bg-green-500' },
                        { key: 'Clean',    color: 'bg-slate-500' },
                      ].filter(({ key }) => riskDistribution.counts[key] > 0).map(({ key, color }) => (
                        <div key={key} className={`${color} opacity-70`}
                          style={{ width: `${(riskDistribution.counts[key] / riskDistribution.total) * 100}%` }} />
                      ))}
                      {riskDistribution.other > 0 && <div className="bg-slate-700 opacity-40 flex-1" />}
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2">
                      {[
                        { key: 'Critical', color: 'bg-red-500' },
                        { key: 'High',     color: 'bg-orange-500' },
                        { key: 'Medium',   color: 'bg-amber-500' },
                        { key: 'Low',      color: 'bg-green-500' },
                        { key: 'Clean',    color: 'bg-slate-500' },
                      ].filter(({ key }) => riskDistribution.counts[key] > 0).map(({ key, color }) => (
                        <div key={key} className="flex items-center gap-1.5 text-xs text-slate-400">
                          <span className={`w-2 h-2 rounded-full ${color} opacity-70`} />
                          {key} ({riskDistribution.counts[key]})
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>

              {/* Most active IOC type */}
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider font-semibold mb-2">Most Active IOC Type</p>
                {!mostActiveIocType ? (
                  <p className="text-slate-600 text-xs">No data yet.</p>
                ) : (
                  <div className="flex items-center gap-3 bg-[#0a0f1e] border border-white/[0.05] rounded-lg px-3 py-2.5">
                    <svg className="w-5 h-5 text-purple-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                    <div>
                      <p className="text-white text-sm font-medium">{IOC_TYPE_LABELS[mostActiveIocType.type] || mostActiveIocType.type}</p>
                      <p className="text-slate-500 text-xs">{mostActiveIocType.count} submission{mostActiveIocType.count !== 1 ? 's' : ''}</p>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* IOC type bar chart */}
            <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                IOC Types
              </h3>
              {iocTypeData.length === 0 ? (
                <div className="h-44 flex items-center justify-center text-slate-600 text-sm">No data yet.</div>
              ) : (
                <ResponsiveContainer width="100%" height={170}>
                  <BarChart data={iocTypeData} barSize={18}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
                    <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} width={24} />
                    <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]} fill="#3b82f6" opacity={0.85} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Recent campaigns */}
          {campaigns.length > 0 && (
            <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                  </svg>
                  Recent Campaigns
                </h3>
                <button
                  onClick={() => navigate('/analyst/campaigns')}
                  className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                >
                  View all →
                </button>
              </div>
              <div className="space-y-2">
                {campaigns.slice(0, 4).map(c => (
                  <div
                    key={c.campaign_id}
                    onClick={() => navigate('/analyst/campaigns')}
                    className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-white/[0.03] transition-colors cursor-pointer"
                  >
                    <div className="w-8 h-8 rounded-lg bg-purple-600/20 border border-purple-500/20 flex items-center justify-center flex-shrink-0">
                      <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                      </svg>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-white truncate">{c.name}</div>
                      <div className="text-xs text-slate-500">{formatDate(c.created_at)} · {c.ioc_count} IOCs · {c.unified_rule_count ?? 0} rules</div>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0">
                      {c.combined_risk_score !== undefined && c.combined_risk_score !== null && (
                        <span className={`text-xs font-semibold ${riskColor(c.combined_risk_level)}`}>
                          {c.combined_risk_score} · {c.combined_risk_level}
                        </span>
                      )}
                      {c.top_apt && (
                        <span className="text-xs text-red-300 truncate max-w-[90px]">{c.top_apt}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* My IOC history table */}
          <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">My IOC History</h3>
              <span className="text-xs text-slate-500">{submissions.length} submissions</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/[0.05]">
                    {['IOC Value', 'Type', 'Submitted At', 'Techniques', 'Risk', 'Status'].map(h => (
                      <th key={h} className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {submissions.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-5 py-12 text-center">
                        <div className="space-y-3">
                          <svg className="w-10 h-10 text-slate-700 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                          </svg>
                          <p className="text-slate-600 text-sm">No IOCs submitted yet.</p>
                          <button onClick={() => navigate('/analyst/submit')} className="text-blue-400 hover:text-blue-300 text-sm underline">
                            Submit your first IOC
                          </button>
                        </div>
                      </td>
                    </tr>
                  ) : (
                    submissions.map(sub => {
                      const parsed = parseResult(sub.result_json);
                      return (
                        <tr key={sub.id} className="border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors">
                          <td className="px-5 py-3.5">
                            <span className="font-mono text-slate-200 text-xs bg-white/[0.05] px-2 py-1 rounded">
                              {sub.ioc_value.length > 40 ? `${sub.ioc_value.slice(0, 37)}...` : sub.ioc_value}
                            </span>
                          </td>
                          <td className="px-5 py-3.5">
                            <span className="text-xs text-slate-400 bg-white/[0.04] px-2 py-1 rounded border border-white/[0.06]">
                              {IOC_TYPE_LABELS[sub.ioc_type] || sub.ioc_type}
                            </span>
                          </td>
                          <td className="px-5 py-3.5 text-slate-500 text-xs whitespace-nowrap">{formatDate(sub.submitted_at)}</td>
                          <td className="px-5 py-3.5">
                            {parsed.techCount > 0 ? (
                              <span className="font-mono text-blue-400 text-xs">
                                {parsed.firstTechId}
                                {parsed.techCount > 1 && <span className="text-slate-500 ml-1">+{parsed.techCount - 1}</span>}
                              </span>
                            ) : (
                              <span className="text-slate-600 text-xs">—</span>
                            )}
                          </td>
                          <td className="px-5 py-3.5"><RiskBadge level={parsed.riskLevel} /></td>
                          <td className="px-5 py-3.5"><StatusBadge hasResult={!!sub.result_json} /></td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Floating Submit IOC button */}
        <button
          onClick={() => navigate('/analyst/submit')}
          className="fixed bottom-8 right-8 flex items-center gap-2.5 bg-blue-600 hover:bg-blue-500 active:scale-95 text-white font-semibold px-5 py-3.5 rounded-full shadow-lg shadow-blue-500/25 transition-all duration-200 z-50"
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Submit New IOC
        </button>
      </main>
    </div>
  );
}
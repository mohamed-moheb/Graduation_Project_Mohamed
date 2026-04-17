import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid,
} from 'recharts';
import api from '../api/client';
import Sidebar from '../components/Sidebar';
import StatCard from '../components/StatCard';
import type { Stats, IOCSubmission, Campaign } from '../types';

const PIE_COLORS = ['#3b82f6', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899'];

const IOC_TYPE_LABELS: Record<string, string> = {
  ip: 'IP Address', domain: 'Domain', url: 'URL', file_hash: 'File Hash',
  email: 'Email', process_command: 'Process', registry_key: 'Registry',
};

function riskColor(level?: string | null) {
  const l = (level || '').toLowerCase();
  if (l === 'critical') return 'text-red-400';
  if (l === 'high')     return 'text-orange-400';
  if (l === 'medium')   return 'text-amber-400';
  if (l === 'low')      return 'text-green-400';
  return 'text-slate-400';
}

function formatDate(dt: string) {
  return new Date(dt).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

interface ParsedResult {
  techCount: number;
  firstTechId: string;
  riskLevel?: string;
  confidence?: number;
  allTechs: Array<{ id: string; tactics?: string[] }>;
}

function parseResult(resultJson: string | null): ParsedResult {
  if (!resultJson) return { techCount: 0, firstTechId: '—', allTechs: [] };
  try {
    const data = JSON.parse(resultJson);
    const techs: unknown[] = data.techniques || [];
    const firstTech = techs[0];
    const firstTechId =
      typeof firstTech === 'string' ? firstTech.split(' ')[0]
      : typeof firstTech === 'object' && firstTech !== null && 'id' in firstTech
        ? String((firstTech as { id: unknown }).id) : '—';
    const conf = data.confidence_metrics as Record<string, number> | undefined;
    const allTechs = techs.map(t =>
      typeof t === 'string'
        ? { id: t.split(' ')[0] }
        : { id: String((t as { id?: unknown }).id || ''), tactics: (t as { tactics?: string[] }).tactics }
    ).filter(t => t.id);
    return { techCount: techs.length, firstTechId: firstTechId || '—', riskLevel: data.risk_level, confidence: conf?.overall_threat_confidence, allTechs };
  } catch { return { techCount: 0, firstTechId: '—', allTechs: [] }; }
}

function tacticBarColor(tactics?: string[]): string {
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
  return 'bg-slate-500';
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

const CustomTooltip = ({ active, payload, label }: { active?: boolean; payload?: { value: number }[]; label?: string }) => {
  if (active && payload?.length) {
    return (
      <div className="bg-[#0f1629] border border-white/[0.1] rounded-lg px-3 py-2 text-xs shadow-xl">
        <p className="text-slate-400">{label}</p>
        <p className="text-blue-400 font-semibold">{payload[0].value} submissions</p>
      </div>
    );
  }
  return null;
};

const PieTooltip = ({ active, payload }: { active?: boolean; payload?: { name: string; value: number }[] }) => {
  if (active && payload?.length) {
    return (
      <div className="bg-[#0f1629] border border-white/[0.1] rounded-lg px-3 py-2 text-xs shadow-xl">
        <p className="text-white font-medium">{IOC_TYPE_LABELS[payload[0].name] || payload[0].name}</p>
        <p className="text-blue-400">{payload[0].value} IOCs</p>
      </div>
    );
  }
  return null;
};

export default function AdminDashboard() {
  const navigate = useNavigate();

  const [stats,       setStats]       = useState<Stats | null>(null);
  const [submissions, setSubmissions] = useState<IOCSubmission[]>([]);
  const [campaigns,   setCampaigns]   = useState<Campaign[]>([]);
  const [loading,     setLoading]     = useState(true);
  const [refreshing,  setRefreshing]  = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);
  const [deleting,    setDeleting]    = useState<number | null>(null);

  const loadDashboardData = useCallback(async (showLoader = false) => {
    try {
      if (showLoader) setLoading(true); else setRefreshing(true);
      const [statsRes, subsRes, campRes] = await Promise.all([
        api.get<Stats>('/submissions/stats'),
        api.get<IOCSubmission[]>('/submissions/all'),
        api.get<Campaign[]>('/api/campaigns/all'),
      ]);
      setStats(statsRes.data);
      setSubmissions(subsRes.data);
      setCampaigns(campRes.data);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { loadDashboardData(true); }, [loadDashboardData]);

  const handleDelete = async (id: number) => {
    setDeleting(id);
    try {
      await api.delete(`/submissions/${id}`);
      setSubmissions(prev => prev.filter(s => s.id !== id));
      const statsRes = await api.get<Stats>('/submissions/stats');
      setStats(statsRes.data);
    } catch (err) { console.error('Delete failed', err); }
    finally { setDeleting(null); setConfirmDeleteId(null); }
  };

  const dailyData = (() => {
    if (!stats?.daily_submissions) return [];
    const map = new Map(stats.daily_submissions.map(d => [d.date, d.count]));
    return Array.from({ length: 7 }, (_, i) => {
      const d = new Date(); d.setDate(d.getDate() - (6 - i));
      const key   = d.toISOString().split('T')[0];
      const label = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      return { date: label, count: map.get(key) || 0 };
    });
  })();

  const topTechniques = useMemo(() => {
    const counts = new Map<string, { count: number; tactics?: string[] }>();
    // Single IOC submissions
    for (const sub of submissions) {
      const { allTechs } = parseResult(sub.result_json);
      for (const t of allTechs) {
        if (!t.id || t.id === '—') continue;
        const existing = counts.get(t.id);
        if (existing) existing.count++; else counts.set(t.id, { count: 1, tactics: t.tactics });
      }
    }
    // Campaign shared techniques
    for (const c of campaigns) {
      for (const st of (c.correlation?.shared_techniques ?? [])) {
        const existing = counts.get(st.technique_id);
        if (existing) existing.count += st.ioc_count;
        else counts.set(st.technique_id, { count: st.ioc_count });
      }
    }
    return Array.from(counts.entries()).map(([id, d]) => ({ id, ...d })).sort((a, b) => b.count - a.count).slice(0, 10);
  }, [submissions, campaigns]);

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

  const maxTechCount = topTechniques[0]?.count || 1;

  return (
    <div className="flex h-screen bg-[#080d1a] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">

        {/* Header */}
        <div className="border-b border-white/[0.06] px-8 py-5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold text-white">Admin Dashboard</h2>
              <p className="text-sm text-slate-500 mt-0.5">Global threat intelligence overview</p>
            </div>
            <button onClick={() => loadDashboardData(false)} disabled={refreshing}
              className="text-xs px-3 py-2 rounded-lg border border-white/[0.08] text-slate-300 hover:bg-white/[0.03] disabled:opacity-50 transition-colors">
              {refreshing ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>

        <div className="px-8 py-6 space-y-6">

          {/* Stat cards — now 5 including Campaigns */}
          <div className="grid grid-cols-2 xl:grid-cols-5 gap-4">
            <StatCard label="Total IOCs" value={stats?.total_submissions ?? 0} color="blue"
              icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>}
              subtitle="Across all analysts" />
            <StatCard label="Analysts" value={stats?.total_analysts ?? 0} color="purple"
              icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z" /></svg>}
              subtitle="Active security analysts" />
            <StatCard label="Campaigns" value={stats?.total_campaigns ?? campaigns.length} color="purple"
              icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>}
              subtitle="Multi-IOC investigations" />
            <StatCard label="Rules Generated" value={stats?.rules_generated ?? 0} color="green"
              icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" /></svg>}
              subtitle="Wazuh detection rules" />
            <StatCard label="APTs Detected" value={stats?.apts_detected ?? 0} color="red"
              icon={<svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" /></svg>}
              subtitle="Threat actor attributions" />
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white mb-4">IOC Type Distribution</h3>
              {stats?.ioc_type_counts && stats.ioc_type_counts.length > 0 ? (
                <div className="flex items-center gap-4">
                  <ResponsiveContainer width={180} height={180}>
                    <PieChart>
                      <Pie data={stats.ioc_type_counts} dataKey="count" nameKey="ioc_type" cx="50%" cy="50%" innerRadius={50} outerRadius={80} strokeWidth={0}>
                        {stats.ioc_type_counts.map((_, i) => (
                          <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} opacity={0.9} />
                        ))}
                      </Pie>
                      <Tooltip content={<PieTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="flex-1 space-y-2">
                    {stats.ioc_type_counts.map((item, i) => (
                      <div key={item.ioc_type} className="flex items-center justify-between text-xs">
                        <div className="flex items-center gap-2">
                          <div className="w-2.5 h-2.5 rounded-sm flex-shrink-0" style={{ background: PIE_COLORS[i % PIE_COLORS.length] }} />
                          <span className="text-slate-400">{IOC_TYPE_LABELS[item.ioc_type] || item.ioc_type}</span>
                        </div>
                        <span className="font-mono text-white font-medium">{item.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="h-44 flex items-center justify-center text-slate-600 text-sm">No submissions yet</div>
              )}
            </div>

            <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-5">
              <h3 className="text-sm font-semibold text-white mb-4">Submissions — Last 7 Days</h3>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={dailyData} barSize={20}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
                  <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} width={28} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                  <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} opacity={0.85} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Top techniques */}
          <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-5">
            <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
              <svg className="w-4 h-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              Most Mapped Techniques
              <span className="ml-auto text-xs text-slate-500 font-normal">Top 10 across all submissions</span>
            </h3>
            {topTechniques.length === 0 ? (
              <div className="h-24 flex items-center justify-center text-slate-600 text-sm">No technique data yet.</div>
            ) : (
              <div className="space-y-2.5">
                {topTechniques.map(tech => {
                  const widthPct = Math.round((tech.count / maxTechCount) * 100);
                  const barColor = tacticBarColor(tech.tactics);
                  return (
                    <div key={tech.id} className="flex items-center gap-3">
                      <span className="font-mono text-blue-400 text-xs w-20 flex-shrink-0">{tech.id}</span>
                      <div className="flex-1 h-5 bg-white/[0.04] rounded-md overflow-hidden relative">
                        <div className={`h-full ${barColor} opacity-60 rounded-md transition-all duration-500`} style={{ width: `${widthPct}%` }} />
                        {tech.tactics && tech.tactics.length > 0 && (
                          <span className="absolute left-2 top-1/2 -translate-y-1/2 text-[10px] text-white/60 font-medium leading-none">
                            {tech.tactics[0]}
                          </span>
                        )}
                      </div>
                      <span className="text-xs font-mono text-white w-8 text-right flex-shrink-0">×{tech.count}</span>
                    </div>
                  );
                })}
              </div>
            )}
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
                <button onClick={() => navigate('/admin/campaigns')} className="text-xs text-blue-400 hover:text-blue-300 transition-colors">
                  View all →
                </button>
              </div>
              <div className="space-y-2">
                {campaigns.slice(0, 4).map(c => (
                  <div key={c.campaign_id} onClick={() => navigate('/admin/campaigns')}
                    className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-white/[0.03] transition-colors cursor-pointer">
                    <div className="w-8 h-8 rounded-lg bg-purple-600/20 border border-purple-500/20 flex items-center justify-center flex-shrink-0">
                      <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                      </svg>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-white truncate">{c.name}</span>
                        <span className="text-xs text-slate-500 flex-shrink-0">by {c.submitted_by}</span>
                      </div>
                      <div className="text-xs text-slate-500">{formatDate(c.created_at)} · {c.ioc_count} IOCs · {c.unified_rule_count ?? 0} rules</div>
                    </div>
                    <div className="flex items-center gap-3 flex-shrink-0">
                      {c.combined_risk_score !== undefined && c.combined_risk_score !== null && (
                        <span className={`text-xs font-semibold ${riskColor(c.combined_risk_level)}`}>
                          {c.combined_risk_score} · {c.combined_risk_level}
                        </span>
                      )}
                      {c.top_apt && <span className="text-xs text-red-300 truncate max-w-[80px]">{c.top_apt}</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Submissions table */}
          <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">All Submissions</h3>
              <span className="text-xs text-slate-500">{submissions.length} total</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-white/[0.05]">
                    {['IOC Value', 'Type', 'Analyst', 'Submitted At', 'Techniques', 'Risk', 'Confidence', 'Status', ''].map((h, i) => (
                      <th key={i} className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {submissions.length === 0 ? (
                    <tr><td colSpan={9} className="px-5 py-10 text-center text-slate-600 text-sm">No submissions yet</td></tr>
                  ) : (
                    submissions.map(sub => {
                      const parsed = parseResult(sub.result_json);
                      const isConfirmingDelete = confirmDeleteId === sub.id;
                      const isDeletingThis     = deleting === sub.id;
                      return (
                        <tr key={sub.id} className="border-b border-white/[0.04] hover:bg-white/[0.02] transition-colors">
                          <td className="px-5 py-3.5">
                            <span className="font-mono text-slate-200 text-xs bg-white/[0.05] px-2 py-1 rounded">
                              {sub.ioc_value.length > 35 ? `${sub.ioc_value.slice(0, 32)}...` : sub.ioc_value}
                            </span>
                          </td>
                          <td className="px-5 py-3.5">
                            <span className="text-xs text-slate-400 bg-white/[0.04] px-2 py-1 rounded border border-white/[0.06]">
                              {IOC_TYPE_LABELS[sub.ioc_type] || sub.ioc_type}
                            </span>
                          </td>
                          <td className="px-5 py-3.5 text-slate-300 text-xs">{sub.submitted_by}</td>
                          <td className="px-5 py-3.5 text-slate-500 text-xs whitespace-nowrap">{formatDate(sub.submitted_at)}</td>
                          <td className="px-5 py-3.5">
                            {parsed.techCount > 0 ? (
                              <span className="font-mono text-blue-400 text-xs">
                                {parsed.firstTechId}
                                {parsed.techCount > 1 && <span className="text-slate-500 ml-1">+{parsed.techCount - 1}</span>}
                              </span>
                            ) : <span className="text-slate-600 text-xs">—</span>}
                          </td>
                          <td className="px-5 py-3.5"><RiskBadge level={parsed.riskLevel} /></td>
                          <td className="px-5 py-3.5">
                            {parsed.confidence !== undefined
                              ? <span className="font-mono text-cyan-400 text-xs">{parsed.confidence}%</span>
                              : <span className="text-slate-600 text-xs">—</span>}
                          </td>
                          <td className="px-5 py-3.5">
                            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${
                              sub.result_json
                                ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                                : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            }`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${sub.result_json ? 'bg-green-400' : 'bg-amber-400'}`} />
                              {sub.result_json ? 'Analyzed' : 'Pending'}
                            </span>
                          </td>
                          <td className="px-5 py-3.5 text-right whitespace-nowrap">
                            {isConfirmingDelete ? (
                              <div className="flex items-center gap-2 justify-end">
                                <span className="text-xs text-slate-400">Delete?</span>
                                <button onClick={() => handleDelete(sub.id)} disabled={isDeletingThis}
                                  className="text-xs px-2 py-1 rounded bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 disabled:opacity-50 transition-colors">
                                  {isDeletingThis ? '...' : 'Yes'}
                                </button>
                                <button onClick={() => setConfirmDeleteId(null)}
                                  className="text-xs px-2 py-1 rounded bg-white/[0.04] text-slate-400 border border-white/[0.08] hover:bg-white/[0.08] transition-colors">
                                  No
                                </button>
                              </div>
                            ) : (
                              <button onClick={() => setConfirmDeleteId(sub.id)}
                                className="text-slate-600 hover:text-red-400 transition-colors p-1 rounded hover:bg-red-500/10" title="Delete submission">
                                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                </svg>
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      </main>
    </div>
  );
}
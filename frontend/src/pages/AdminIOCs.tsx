import { useEffect, useState } from 'react';
import api from '../api/client';
import Sidebar from '../components/Sidebar';
import type { IOCSubmission } from '../types';

const IOC_TYPE_LABELS: Record<string, string> = {
  ip: 'IP Address', domain: 'Domain', url: 'URL', file_hash: 'File Hash',
  email: 'Email', process_command: 'Process', registry_key: 'Registry',
};

interface ParsedResult {
  techCount: number;
  firstTechId: string;
  riskLevel?: string;
  confidence?: number;
}

function parseResult(resultJson: string | null): ParsedResult {
  if (!resultJson) return { techCount: 0, firstTechId: '—' };
  try {
    const data = JSON.parse(resultJson);
    const techs: unknown[] = data.techniques || [];
    const firstTech = techs[0];
    const firstTechId =
      typeof firstTech === 'string'
        ? firstTech.split(' ')[0]
        : typeof firstTech === 'object' && firstTech !== null && 'id' in firstTech
        ? String((firstTech as { id: unknown }).id)
        : '—';
    const conf = data.confidence_metrics as Record<string, number> | undefined;
    return {
      techCount: techs.length,
      firstTechId: firstTechId || '—',
      riskLevel: data.risk_level,
      confidence: conf?.overall_threat_confidence,
    };
  } catch {
    return { techCount: 0, firstTechId: '—' };
  }
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

function formatDate(dt: string) {
  return new Date(dt).toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function AdminIOCs() {
  const [submissions, setSubmissions] = useState<IOCSubmission[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [confirmingId, setConfirmingId] = useState<number | null>(null);
  const [deleting, setDeleting] = useState<number | null>(null);

  useEffect(() => {
    api.get<IOCSubmission[]>('/submissions/all')
      .then((res) => setSubmissions(res.data))
      .finally(() => setLoading(false));
  }, []);

  const filtered = submissions.filter(
    (s) =>
      s.ioc_value.toLowerCase().includes(search.toLowerCase()) ||
      s.submitted_by.toLowerCase().includes(search.toLowerCase())
  );

  const handleDelete = async (id: number) => {
    setDeleting(id);
    try {
      await api.delete(`/submissions/${id}`);
      setSubmissions((prev) => prev.filter((s) => s.id !== id));
    } catch {
      // Delete failed — keep row
    } finally {
      setDeleting(null);
      setConfirmingId(null);
    }
  };

  return (
    <div className="flex h-screen bg-[#080d1a] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="border-b border-white/[0.06] px-8 py-5">
          <h2 className="text-xl font-semibold text-white">All IOCs</h2>
          <p className="text-sm text-slate-500 mt-0.5">All indicators submitted across the platform</p>
        </div>

        <div className="px-8 py-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="relative flex-1 max-w-sm">
              <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
              </svg>
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search IOCs or analysts..."
                className="w-full bg-[#0f1629] border border-white/[0.08] rounded-lg pl-9 pr-4 py-2.5 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-blue-500/50"
              />
            </div>
            <span className="text-xs text-slate-500">{filtered.length} result{filtered.length !== 1 ? 's' : ''}</span>
          </div>

          <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl overflow-hidden">
            {loading ? (
              <div className="py-16 flex items-center justify-center">
                <svg className="w-6 h-6 spin text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path d="M21 12a9 9 0 11-6.219-8.56"/>
                </svg>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-white/[0.05]">
                      {['IOC Value', 'Type', 'Analyst', 'Submitted At', 'Techniques', 'Risk', 'Confidence', 'Status', ''].map((h) => (
                        <th key={h} className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider last:w-20">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.length === 0 ? (
                      <tr><td colSpan={9} className="px-5 py-10 text-center text-slate-600 text-sm">No IOCs found.</td></tr>
                    ) : (
                      filtered.map((sub) => {
                        const parsed = parseResult(sub.result_json);
                        const isConfirming = confirmingId === sub.id;
                        const isDeleting = deleting === sub.id;
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
                              ) : (
                                <span className="text-slate-600 text-xs">—</span>
                              )}
                            </td>
                            <td className="px-5 py-3.5"><RiskBadge level={parsed.riskLevel} /></td>
                            <td className="px-5 py-3.5">
                              {parsed.confidence !== undefined ? (
                                <span className="font-mono text-cyan-400 text-xs">{parsed.confidence}%</span>
                              ) : (
                                <span className="text-slate-600 text-xs">—</span>
                              )}
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
                            {/* Delete button / inline confirmation */}
                            <td className="px-4 py-3.5">
                              {isDeleting ? (
                                <svg className="w-4 h-4 spin text-slate-500 mx-auto" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                  <path d="M21 12a9 9 0 11-6.219-8.56"/>
                                </svg>
                              ) : isConfirming ? (
                                <div className="flex items-center gap-1.5">
                                  <span className="text-xs text-slate-400">Delete?</span>
                                  <button
                                    onClick={() => handleDelete(sub.id)}
                                    className="text-xs px-2 py-0.5 rounded bg-red-500/20 border border-red-500/30 text-red-400 hover:bg-red-500/30 transition-colors"
                                  >
                                    Yes
                                  </button>
                                  <button
                                    onClick={() => setConfirmingId(null)}
                                    className="text-xs px-2 py-0.5 rounded bg-white/[0.04] border border-white/[0.08] text-slate-400 hover:text-white transition-colors"
                                  >
                                    No
                                  </button>
                                </div>
                              ) : (
                                <button
                                  onClick={() => setConfirmingId(sub.id)}
                                  className="p-1.5 rounded-lg text-slate-600 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                                  title="Delete submission"
                                >
                                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
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
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

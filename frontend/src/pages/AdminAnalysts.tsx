import { useEffect, useState } from 'react';
import api from '../api/client';
import Sidebar from '../components/Sidebar';
import type { IOCSubmission } from '../types';

interface AnalystSummary {
  username: string;
  submissionCount: number;
  lastActive: string | null;
}

export default function AdminAnalysts() {
  const [submissions, setSubmissions] = useState<IOCSubmission[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get<IOCSubmission[]>('/submissions/all')
      .then((res) => setSubmissions(res.data))
      .finally(() => setLoading(false));
  }, []);

  // Aggregate per analyst
  const analystMap = new Map<string, AnalystSummary>();
  for (const sub of submissions) {
    const existing = analystMap.get(sub.submitted_by);
    if (!existing) {
      analystMap.set(sub.submitted_by, {
        username: sub.submitted_by,
        submissionCount: 1,
        lastActive: sub.submitted_at,
      });
    } else {
      existing.submissionCount += 1;
      if (!existing.lastActive || sub.submitted_at > existing.lastActive) {
        existing.lastActive = sub.submitted_at;
      }
    }
  }
  const analysts = Array.from(analystMap.values()).sort((a, b) => b.submissionCount - a.submissionCount);

  function formatDate(dt: string | null) {
    if (!dt) return '—';
    return new Date(dt).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  return (
    <div className="flex h-screen bg-[#080d1a] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="border-b border-white/[0.06] px-8 py-5">
          <h2 className="text-xl font-semibold text-white">Analysts</h2>
          <p className="text-sm text-slate-500 mt-0.5">Active analysts and their submission activity</p>
        </div>

        <div className="px-8 py-6">
          {loading ? (
            <div className="py-16 flex items-center justify-center">
              <svg className="w-6 h-6 spin text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path d="M21 12a9 9 0 11-6.219-8.56" />
              </svg>
            </div>
          ) : analysts.length === 0 ? (
            <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl py-16 text-center text-slate-600 text-sm">
              No analyst activity recorded yet.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {analysts.map((analyst) => (
                <div
                  key={analyst.username}
                  className="bg-[#0f1629] border border-white/[0.07] rounded-xl p-5 flex items-start gap-4"
                >
                  <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-600 to-indigo-800 flex items-center justify-center text-white text-sm font-bold flex-shrink-0">
                    {analyst.username[0]?.toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-white font-semibold text-sm truncate">{analyst.username}</p>
                    <p className="text-slate-500 text-xs mt-0.5">Last active: {formatDate(analyst.lastActive)}</p>
                    <div className="flex items-center gap-3 mt-3">
                      <div className="text-center">
                        <p className="text-blue-400 text-lg font-bold leading-none">{analyst.submissionCount}</p>
                        <p className="text-slate-600 text-xs mt-0.5">Submissions</p>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

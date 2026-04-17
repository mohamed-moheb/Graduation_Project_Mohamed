import { useEffect, useState } from 'react';
import api from '../api/client';
import Sidebar from '../components/Sidebar';
import type { IOCSubmission, WazuhRule, Campaign } from '../types';

interface DetectionGroup {
  ioc_value:     string;
  ioc_type:      string;
  submitted_by:  string;
  submitted_at:  string;
  submission_id: number;
  source:        'single' | 'campaign';
  campaign_name?: string;
  rules:         WazuhRule[];
}

interface ProactiveGroup {
  ioc_value:           string;
  ioc_type:            string;
  submitted_by:        string;
  submitted_at:        string;
  submission_id:       number;
  analyst:             string;
  projected_at:        string;
  apt_name:            string;
  next_technique_id:   string;
  next_technique_name: string;
  why:                 string;
  confidence_level:    string;
  confidence_score:    number;
  source:              'single' | 'campaign';
  campaign_name?:      string;
  rules:               WazuhRule[];
}

const IOC_TYPE_LABELS: Record<string, string> = {
  ip: 'IP', domain: 'Domain', url: 'URL', file_hash: 'Hash',
  email: 'Email', process_command: 'Process', registry_key: 'Registry',
};

function formatDate(dt: string) {
  if (!dt) return '—';
  return new Date(dt).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function SourceBadge({ source, name }: { source: 'single' | 'campaign'; name?: string }) {
  if (source === 'campaign') {
    return (
      <span className="text-xs px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400 flex-shrink-0">
        Campaign{name ? `: ${name}` : ''}
      </span>
    );
  }
  return (
    <span className="text-xs px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 flex-shrink-0">
      Single IOC
    </span>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); })}
      className="flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-white/[0.04] border border-white/[0.08] text-slate-400 hover:text-white transition-colors"
    >
      {copied
        ? <><svg className="w-3 h-3 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}><path d="M5 13l4 4L19 7"/></svg><span className="text-green-400">Copied</span></>
        : <><svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>Copy</>
      }
    </button>
  );
}

function RuleXML({ rule }: { rule: WazuhRule }) {
  const [open, setOpen] = useState(false);
  const xml   = rule.wazuh_xml || JSON.stringify(rule, null, 2);
  const desc  = rule.description || '';
  const level = (rule as Record<string, unknown>).wazuh_level as number | undefined;
  return (
    <div className="bg-[#080d1a] border border-white/[0.06] rounded-lg overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-white/[0.05]">
        <span className="font-mono text-amber-400 text-xs">#{rule.rule_id ?? '—'}</span>
        <span className="text-slate-400 text-xs flex-1 truncate">{desc}</span>
        <div className="flex items-center gap-1.5 ml-auto flex-shrink-0">
          {level !== undefined && (
            <span className="text-xs px-1.5 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-400">Lvl {level}</span>
          )}
          {rule.mitre?.map((m, i) => (
            <span key={i} className="font-mono text-xs px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">{m}</span>
          ))}
          <CopyButton text={xml} />
          <button onClick={() => setOpen(v => !v)} className="text-slate-600 hover:text-white transition-colors ml-1">
            <svg className={`w-4 h-4 transition-transform ${open ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/>
            </svg>
          </button>
        </div>
      </div>
      {open && (
        <pre className="text-xs text-green-300 leading-relaxed p-3 overflow-x-auto max-h-56 overflow-y-auto">
          <code>{xml}</code>
        </pre>
      )}
    </div>
  );
}

function DetectionGroupCard({ group }: { group: DetectionGroup }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="bg-[#0f1629] border border-white/[0.07] rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-white/[0.02] transition-colors text-left"
      >
        <span className="text-xs px-1.5 py-0.5 rounded bg-white/[0.06] text-slate-400 font-mono uppercase flex-shrink-0">
          {IOC_TYPE_LABELS[group.ioc_type] || group.ioc_type}
        </span>
        <span className="font-mono text-blue-300 text-sm truncate flex-1">
          {group.ioc_value.length > 45 ? `${group.ioc_value.slice(0, 42)}...` : group.ioc_value}
        </span>
        <SourceBadge source={group.source} name={group.campaign_name} />
        <span className="text-xs text-slate-500 flex-shrink-0">{group.submitted_by}</span>
        <span className="text-xs text-slate-600 flex-shrink-0">{formatDate(group.submitted_at)}</span>
        <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 flex-shrink-0">
          {group.rules.length} rule{group.rules.length !== 1 ? 's' : ''}
        </span>
        <svg className={`w-4 h-4 text-slate-600 flex-shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/>
        </svg>
      </button>
      {open && (
        <div className="px-5 pb-4 space-y-2 border-t border-white/[0.05] pt-3">
          {group.rules.map((rule, i) => <RuleXML key={rule.rule_id ?? i} rule={rule} />)}
        </div>
      )}
    </div>
  );
}

function ProactiveGroupCard({ group }: { group: ProactiveGroup }) {
  const [open, setOpen] = useState(false);
  const confidenceColor =
    group.confidence_level === 'High'   ? 'text-green-400' :
    group.confidence_level === 'Medium' ? 'text-amber-400' : 'text-red-400';

  return (
    <div className={`bg-[#0f1629] rounded-xl overflow-hidden border ${
      group.source === 'campaign' ? 'border-purple-500/25' : 'border-purple-500/20'
    }`}>
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-white/[0.02] transition-colors text-left"
      >
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="w-2 h-2 rounded-full bg-purple-400 flex-shrink-0" />
          <span className="text-purple-300 text-sm font-semibold">{group.apt_name}</span>
        </div>
        <svg className="w-4 h-4 text-slate-600 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6"/>
        </svg>
        <span className="font-mono text-white text-sm font-bold flex-shrink-0">{group.next_technique_id}</span>
        {group.next_technique_name && (
          <span className="text-slate-300 text-xs truncate flex-1">{group.next_technique_name}</span>
        )}
        <span className={`text-xs font-semibold flex-shrink-0 ${confidenceColor}`}>
          {group.confidence_score}% {group.confidence_level}
        </span>
        <SourceBadge source={group.source} name={group.campaign_name} />
        <span className="text-xs flex-shrink-0">
          <span className="text-slate-600">by </span>
          <span className="text-slate-300 font-medium">{group.analyst}</span>
        </span>
        <span className="text-xs px-2 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-400 flex-shrink-0">
          {group.rules.length} rule{group.rules.length !== 1 ? 's' : ''}
        </span>
        <svg className={`w-4 h-4 text-slate-600 flex-shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7"/>
        </svg>
      </button>

      {open && (
        <div className="border-t border-purple-500/10">
          {/* FIX: IOC value always shown — moved outside the group.why condition */}
          <div className="px-5 py-3 bg-purple-500/5 border-b border-purple-500/10">
            {group.why && (
              <p className="text-xs text-slate-400 leading-relaxed mb-2">
                <span className="text-purple-400 font-semibold">Why this is next: </span>
                {group.why}
              </p>
            )}
            <div className="flex items-center gap-3 text-xs text-slate-500 flex-wrap">
              {group.source === 'campaign' ? (
                <span>Campaign: <span className="text-slate-300">{group.campaign_name}</span></span>
              ) : (
                <span>IOC: <span className="text-slate-300 font-mono">{group.ioc_value}</span></span>
              )}
              <span>·</span>
              <span>Projected by: <span className="text-slate-300 font-medium">{group.analyst}</span></span>
              {group.projected_at && <><span>·</span><span>{formatDate(group.projected_at)}</span></>}
            </div>
          </div>
          <div className="px-5 pb-4 space-y-2 pt-3">
            {group.rules.length === 0 ? (
              <p className="text-xs text-slate-600 py-4 text-center">No proactive rules generated for this projection.</p>
            ) : (
              group.rules.map((rule, i) => <RuleXML key={rule.rule_id ?? i} rule={rule} />)
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function parseProactiveGroups(
  parsed: Record<string, unknown>,
  meta: { ioc_value: string; ioc_type: string; submitted_by: string; submitted_at: string; submission_id: number }
): ProactiveGroup[] {
  const groups: ProactiveGroup[] = [];

  if ('apt_projections' in parsed) {
    const list = Array.isArray(parsed.apt_projections) ? parsed.apt_projections as Record<string, unknown>[] : [];
    for (const projection of list) {
      const predictedRules = Array.isArray(projection.predicted_rules) ? projection.predicted_rules as WazuhRule[] : [];
      const pnt  = ((projection.predicted_next_step as Record<string, unknown> | undefined)?.predicted_next_technique as Record<string, unknown> | undefined) || {};
      const conf = ((projection.predicted_next_step as Record<string, unknown> | undefined)?.confidence as Record<string, unknown> | undefined) || {};
      const sa   = (projection.selected_apt as Record<string, unknown> | undefined) || {};
      groups.push({
        ...meta,
        source:              'single',
        analyst:             String(projection.analyst || 'unknown'),
        projected_at:        String(projection.projected_at || ''),
        apt_name:            String(sa.apt_name || predictedRules[0]?.mitre?.[0] || 'Unknown APT'),
        next_technique_id:   String(pnt.id || predictedRules[0]?.mitre?.[0] || '—'),
        next_technique_name: String(pnt.name || ''),
        why:                 String(pnt.why_this_is_next || ''),
        confidence_level:    String(conf.level || ''),
        confidence_score:    Number(conf.score || 0),
        rules:               predictedRules,
      });
    }
    return groups;
  }

  const predictedRules: WazuhRule[] = Array.isArray(parsed.predicted_rules) ? parsed.predicted_rules as WazuhRule[] : [];
  if (predictedRules.length === 0) return groups;
  const projection = (parsed.predicted_next_step as Record<string, unknown> | undefined) || {};
  const pnt  = (projection.predicted_next_technique as Record<string, unknown> | undefined) || {};
  const conf = (projection.confidence as Record<string, unknown> | undefined) || {};
  const sa   = (parsed.selected_apt as Record<string, unknown> | undefined) || {};
  const firstRule = predictedRules[0] as Record<string, unknown>;
  groups.push({
    ...meta,
    source:              'single',
    analyst:             String(meta.submitted_by),
    projected_at:        String(meta.submitted_at),
    apt_name:            String(sa.apt_name || firstRule?.apt_name || 'Unknown APT'),
    next_technique_id:   String(pnt.id || predictedRules[0]?.mitre?.[0] || '—'),
    next_technique_name: String(pnt.name || ''),
    why:                 String(pnt.why_this_is_next || ''),
    confidence_level:    String(conf.level || ''),
    confidence_score:    Number(conf.score || 0),
    rules:               predictedRules,
  });
  return groups;
}

async function fetchCampaignIocValues(): Promise<Set<string>> {
  try {
    const campRes = await api.get<Campaign[]>('/api/campaigns/all');
    const values = new Set<string>();
    for (const camp of campRes.data) {
      try {
        const detail = await api.get<Campaign>(`/api/campaign/${camp.campaign_id}`);
        for (const ioc of detail.data.ioc_results ?? []) {
          if (ioc.ioc_value) values.add(ioc.ioc_value);
        }
      } catch { /* skip */ }
    }
    return values;
  } catch {
    return new Set();
  }
}

export default function AdminRules() {
  const [detectionGroups, setDetectionGroups] = useState<DetectionGroup[]>([]);
  const [proactiveGroups, setProactiveGroups] = useState<ProactiveGroup[]>([]);
  const [loading,   setLoading]   = useState(true);
  const [activeTab, setActiveTab] = useState<'detection' | 'proactive'>('detection');

  useEffect(() => {
    const loadAll = async () => {
      const detection: DetectionGroup[] = [];
      const proactive: ProactiveGroup[] = [];

      // FIX: build a set of IOC values that were submitted via campaigns
      // so we can exclude them from the single-IOC detection list
      const campaignIocValues = await fetchCampaignIocValues();

      try {
        const subRes = await api.get<IOCSubmission[]>('/submissions/all');
        for (const sub of subRes.data) {
          if (!sub.result_json) continue;
          let parsed: Record<string, unknown>;
          try { parsed = JSON.parse(sub.result_json); } catch { continue; }

          const meta = {
            ioc_value:     sub.ioc_value,
            ioc_type:      sub.ioc_type,
            submitted_by:  sub.submitted_by,
            submitted_at:  sub.submitted_at,
            submission_id: sub.id,
          };

          const candidateRules: WazuhRule[] = (() => {
            if (Array.isArray(parsed.candidate_rules)) return parsed.candidate_rules as WazuhRule[];
            if (Array.isArray(parsed.detection_rules)) return parsed.detection_rules as WazuhRule[];
            return [];
          })();

          // Only add as single IOC if NOT a campaign-mirrored entry
          if (candidateRules.length > 0 && !campaignIocValues.has(sub.ioc_value)) {
            detection.push({ ...meta, source: 'single', rules: candidateRules });
          }

          const groups = parseProactiveGroups(parsed, meta);
          proactive.push(...groups);
        }
      } catch { /* silent */ }

      try {
        const campRes = await api.get<Campaign[]>('/api/campaigns/all');
        for (const camp of campRes.data) {
          try {
            const detail = await api.get<Campaign>(`/api/campaign/${camp.campaign_id}`);
            const corr = detail.data.correlation;
            if (!corr) continue;

            const campaignRules = (corr.unified_rules ?? []).filter(
              r => r.candidate_type !== 'campaign_proactive' && r.candidate_type !== 'proactive_blueprint'
            );
            if (campaignRules.length > 0) {
              detection.push({
                ioc_value:     camp.name ?? `Campaign #${camp.campaign_id}`,
                ioc_type:      'campaign',
                submitted_by:  camp.submitted_by,
                submitted_at:  camp.created_at,
                submission_id: camp.campaign_id,
                source:        'campaign',
                campaign_name: camp.name,
                rules:         campaignRules,
              });
            }

            const proj = corr.campaign_apt_projection;
            if (proj && Array.isArray(proj.predicted_rules) && proj.predicted_rules.length > 0) {
              const pnt  = (proj.predicted_next_step as Record<string,unknown>)?.predicted_next_technique as Record<string,unknown> | undefined || {};
              const conf = (proj.predicted_next_step as Record<string,unknown>)?.confidence as Record<string,unknown> | undefined || {};
              proactive.push({
                ioc_value:           camp.name ?? `Campaign #${camp.campaign_id}`,
                ioc_type:            'campaign',
                submitted_by:        camp.submitted_by,
                submitted_at:        camp.created_at,
                submission_id:       camp.campaign_id,
                analyst:             String(proj.analyst || camp.submitted_by),
                projected_at:        String(proj.projected_at || camp.created_at),
                apt_name:            String((proj.selected_apt as { apt_name?: string } | undefined)?.apt_name || 'Unknown APT'),
                next_technique_id:   String(pnt.id || '—'),
                next_technique_name: String(pnt.name || ''),
                why:                 String(pnt.why_this_is_next || ''),
                confidence_level:    String(conf.level || ''),
                confidence_score:    Number(conf.score || 0),
                source:              'campaign',
                campaign_name:       camp.name,
                rules:               proj.predicted_rules,
              });
            }
          } catch { /* skip */ }
        }
      } catch { /* silent */ }

      setDetectionGroups(detection);
      setProactiveGroups(proactive);
      setLoading(false);
    };

    loadAll();
  }, []);

  const totalDetection = detectionGroups.reduce((s, g) => s + g.rules.length, 0);
  const totalProactive = proactiveGroups.reduce((s, g) => s + g.rules.length, 0);

  return (
    <div className="flex h-screen bg-[#080d1a] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="border-b border-white/[0.06] px-8 py-5">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold text-white">Detection Rules</h2>
            </div>
            {!loading && (
              <div className="flex items-center gap-4 text-xs text-slate-400">
                <span>Detection: <span className="text-blue-400 font-semibold">{totalDetection}</span></span>
                <span>Proactive: <span className="text-purple-400 font-semibold">{totalProactive}</span></span>
                <span>Total: <span className="text-white font-semibold">{totalDetection + totalProactive}</span></span>
              </div>
            )}
          </div>
          <div className="flex gap-1 mt-4">
            {[
              { id: 'detection' as const, label: 'Detection Rules', count: detectionGroups.length, color: 'blue' },
              { id: 'proactive' as const, label: 'Proactive Rules', count: proactiveGroups.length, color: 'purple' },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-5 py-2 text-sm font-medium rounded-lg transition-all ${
                  activeTab === tab.id
                    ? tab.color === 'blue'
                      ? 'bg-blue-500/15 text-blue-400 border border-blue-500/30'
                      : 'bg-purple-500/15 text-purple-400 border border-purple-500/30'
                    : 'text-slate-400 hover:text-white hover:bg-white/[0.04]'
                }`}
              >
                {tab.label}
                <span className={`ml-2 text-xs px-1.5 py-0.5 rounded-full ${
                  activeTab === tab.id
                    ? tab.color === 'blue' ? 'bg-blue-500/20 text-blue-400' : 'bg-purple-500/20 text-purple-400'
                    : 'bg-white/[0.06] text-slate-500'
                }`}>
                  {tab.count}
                </span>
              </button>
            ))}
          </div>
        </div>

        <div className="px-8 py-6 space-y-3">
          {loading ? (
            <div className="py-16 flex items-center justify-center">
              <svg className="w-6 h-6 spin text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path d="M21 12a9 9 0 11-6.219-8.56"/>
              </svg>
            </div>
          ) : activeTab === 'detection' ? (
            detectionGroups.length === 0 ? (
              <div className="py-20 text-center text-slate-600 text-sm">No detection rules generated yet.</div>
            ) : (
              detectionGroups.map((group, i) => (
                <DetectionGroupCard key={`${group.source}-${group.submission_id}-${i}`} group={group} />
              ))
            )
          ) : (
            proactiveGroups.length === 0 ? (
              <div className="py-20 text-center">
                <p className="text-slate-600 text-sm">No proactive rules yet.</p>
                <p className="text-slate-700 text-xs mt-1">
                  Run APT projection on a submitted IOC or campaign to generate proactive rules.
                </p>
              </div>
            ) : (
              proactiveGroups.map((group, i) => (
                <ProactiveGroupCard key={`${group.source}-${group.submission_id}-${group.apt_name}-${i}`} group={group} />
              ))
            )
          )}
        </div>
      </main>
    </div>
  );
}
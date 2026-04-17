export interface User {
  username: string;
  role: 'admin' | 'analyst';
}

export interface IOCSubmission {
  id: number;
  ioc_type: string;
  ioc_value: string;
  context: string | null;
  submitted_by: string;
  submitted_at: string;
  result_json: string | null;
  rule_hash: string | null;
}

export interface Stats {
  total_submissions: number;
  total_analysts?: number;
  total_campaigns?: number;
  rules_generated: number;
  apts_detected: number;
  ioc_type_counts: { ioc_type: string; count: number }[];
  daily_submissions?: { date: string; count: number }[];
}

export interface TechniqueResult {
  id: string;
  name?: string;
  reason?: string;
  tactics?: string[];
  rule_count?: number;
}

export interface CandidateApt {
  apt_name: string;
  matching_techniques: number;
  total_known_techniques: number;
}

export interface WazuhRule {
  wazuh_xml?: string;
  rule_id?: number;
  description?: string;
  mitre?: string[];
  candidate_type?: string;
  apt_name?: string;
  predicted_tid?: string;
  [key: string]: unknown;
}

export interface PipelineResult {
  techniques?: Array<TechniqueResult | string>;
  detection_rules?: string | WazuhRule[] | object;
  candidate_rules?: WazuhRule[];
  apt_projection?: {
    predicted_next_technique?: { id?: string; name?: string; why_this_is_next?: string; tactic?: string };
    confidence?: { score?: number; level?: string; justification?: string };
    source?: string;
    [key: string]: unknown;
  } | string | object;
  predicted_next_step?: object;
  apt_groups?: string[];
  apts?: string[];
  candidate_apts?: Array<CandidateApt | string>;
  validated_techniques?: Array<string | TechniqueResult>;
  enrichment?: object;
  rag_validation?: object;
  confidence_metrics?: object;
  primary_technique?: { id?: string; name?: string; tactics?: string[] };
  risk_score?: number;
  risk_level?: string;
  apt_projections?: AptProjection[];
  raw?: object;
  [key: string]: unknown;
}

export type StageStatus = 'idle' | 'active' | 'completed' | 'error';

export interface PipelineStage {
  id: string;
  name: string;
  status: StageStatus;
  preview?: string;
  data?: object;
}

// ── Campaign types ────────────────────────────────────────────────
export interface CampaignIOCItem {
  ioc_type: string;
  ioc_value: string;
  context: string;
}

export interface KillChainEntry {
  tactic: string;
  stage_index: number;
  covered: boolean;
  technique_count: number;
  techniques: string[];
}

export interface SharedTechnique {
  technique_id: string;
  ioc_indices: number[];
  ioc_count: number;
}

export interface CampaignCorrelation {
  total_iocs: number;
  total_unique_techniques: number;
  shared_techniques: SharedTechnique[];
  kill_chain_map: KillChainEntry[];
  gap_tactics: string[];
  campaign_apt_candidates: CandidateApt[];
  top_apt: CandidateApt | null;
  combined_risk_score: number;
  combined_risk_level: string;
  unified_rule_count: number;
  unified_rules: WazuhRule[];
  correlated_at: string;
  campaign_apt_projection?: {
    analyst: string;
    projected_at: string;
    selected_apt: CandidateApt;
    all_techniques: string[];
    candidate_next: string[];
    predicted_next_step: {
      predicted_next_technique?: { id?: string; name?: string; tactic?: string; why_this_is_next?: string };
      confidence?: { score?: number; level?: string; justification?: string };
      source?: string;
    };
    predicted_rules: WazuhRule[];
  };
}

export interface CampaignIOCResult {
  id: number;
  campaign_id: number;
  ioc_type: string;
  ioc_value: string;
  context: string;
  result_json: PipelineResult;
  submission_id: number | null;
}

export interface Campaign {
  campaign_id: number;
  name?: string;
  campaign_name?: string;       // returned by backend on submit
  description: string;
  submitted_by: string;
  created_at: string;
  status: 'pending' | 'processing' | 'complete';
  ioc_count: number;
  analyzed_count?: number;      // how many IOCs were successfully analyzed
  failed_iocs?: { ioc_value: string; ioc_type: string; error: string }[];
  ioc_results?: CampaignIOCResult[];
  correlation?: CampaignCorrelation;
  // summary fields (list views)
  combined_risk_score?: number;
  combined_risk_level?: string;
  unified_rule_count?: number;
  top_apt?: string;
  gap_tactics?: string[];
}

export interface AptProjection {
  analyst: string;
  projected_at: string;
  selected_apt: CandidateApt | null;
  predicted_next_step: object | null;
  predicted_rules: WazuhRule[];
  candidate_next_techniques: string[];
}
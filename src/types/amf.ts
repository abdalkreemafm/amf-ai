export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RunMode = 'dry-run' | 'execute';

export interface ModuleInfo {
  name: string;
  description: string;
  category: string;
  risk: string;
  tags: string[];
  references: string[];
}

export interface Finding {
  module: string;
  title: string;
  title_ar: string;
  title_en: string;
  severity: Severity;
  confidence: string;
  type: string;
  description: string;
  description_ar: string;
  description_en: string;
  impact_ar: string;
  impact_en: string;
  remediation_ar: string;
  remediation_en: string;
  evidence: Record<string, unknown>;
}

export interface RunResult {
  module: string;
  target: string;
  mode: RunMode;
  started_at: string;
  findings: Finding[];
  error: string | null;
}

export interface Job {
  id: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  total: number;
  current_module: string | null;
  results: RunResult[];
  error: string | null;
}

export interface ProfileInfo {
  name: string;
  description: string;
  module_count: number;
}

export interface IntelObservation {
  asset: string;
  source: string;
  kind: 'potential-match' | 'reference-only' | 'needs-review';
  value: string;
  confidence: string;
  observed_at: string;
  evidence: Record<string, unknown>;
}

export interface NVDAdvisory {
  cve_id: string;
  summary: string;
  severity: string;
  cvss_score: number | null;
  published_at?: string | null;
  modified_at?: string | null;
  references: string[];
  product_matches: Array<{ cpe_name: string; confidence: string; matching_reason: string; vulnerable: boolean }>;
  evidence: { source: string; retrieved_at: string; source_url: string; [key: string]: unknown };
}

export interface NVDLookupResponse {
  advisories: NVDAdvisory[];
  correlation: { assets: Array<Record<string, unknown>>; observations: IntelObservation[]; duplicate_groups: number };
  notice: string;
}

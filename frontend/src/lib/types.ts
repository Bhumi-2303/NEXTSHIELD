export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

export interface SHAPFeature {
  feature_name: string;
  shap_value: number;
}

export interface SHAPExplanation {
  features: SHAPFeature[];
  base_value: number;
  summary: string;
}

export interface ThreatAlert {
  id: string;
  source_module: string; // e.g., 'phishing', 'anomaly'
  timestamp: string;     // ISO 8601
  severity: SeverityLevel;
  mitre_technique_id: string; // e.g., 'T1566'
  confidence_score: number;
  explanation: SHAPExplanation;
  raw_payload?: Record<string, any>;
}

export interface PlaybookStep {
  action: string;
  description: string;
  automatable: boolean;
}

export interface Playbook {
  id: string;
  mitre_technique_id: string;
  title: string;
  severity_threshold: SeverityLevel;
  steps: PlaybookStep[];
  estimated_response_time_minutes: number;
}

export interface SimulationTimelineEntry {
  step_number: number;
  action: string;
  automatable: boolean;
  status: 'completed' | 'pending_human_action';
  executed_at: string | null;
  duration_seconds: number | null;
  result: string;
}

export interface SimulationResult {
  playbook_id: string;
  playbook_title: string;
  mitre_technique_id: string;
  simulation_started_at: string;
  total_steps: number;
  automated_steps_completed: number;
  manual_steps_pending: number;
  estimated_response_time_minutes: number;
  timeline: SimulationTimelineEntry[];
}

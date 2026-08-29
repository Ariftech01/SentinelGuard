export type SecurityAction = 'ALLOWED' | 'MASKED' | 'BLOCKED';
export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  user: string;
  data: string;
  score: number;
  risk_level: RiskLevel;
  action: SecurityAction;
  provider: string;
  model?: string;
  policy: string;
  latency_ms?: number;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  when: string[];
  when_label: string;
  risk: RiskLevel;
  then: 'ALLOW' | 'MASK' | 'BLOCK';
  enabled: boolean;
}

export interface ProviderStatus {
  name: string;
  status: 'connected' | 'not-configured';
  uptime?: string;
  kind?: string;
}

export interface DetectedItem {
  type: string;
  label: string;
  count: number;
  original: string;
  masked: string;
}

export interface ChatDecision {
  action: SecurityAction;
  score: number;
  risk_level: RiskLevel;
  policy: string;
  detected: DetectedItem[];
}

export interface ChatResult {
  event_id: string;
  decision: ChatDecision;
  masked_message: string | null;
  response: string | null;
  error: string | null;
  output_masked: boolean;
  latency_ms: number;
  provider: string;
}

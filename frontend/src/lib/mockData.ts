import { ThreatAlert, Playbook } from './types';

export const mockAlerts: ThreatAlert[] = [
  {
    id: 'ALT-20260801-001',
    source_module: 'phishing',
    timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    severity: 'high',
    mitre_technique_id: 'T1566',
    confidence_score: 0.88,
    explanation: {
      top_features: [
        { feature_name: 'Urgency Score', shap_value: 0.45 },
        { feature_name: 'Lookalike Domain', shap_value: 0.35 },
        { feature_name: 'SPF Pass', shap_value: -0.1 },
      ],
      base_value: 0.2,
      summary: 'High confidence phishing attempt based on extreme urgency language and a lookalike sender domain.',
    },
    raw_payload: { sender: 'support@paypa1.com', subject: 'Account Suspended' },
  },
  {
    id: 'ALT-20260801-002',
    source_module: 'anomaly',
    timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    severity: 'critical',
    mitre_technique_id: 'T1071',
    confidence_score: 0.94,
    explanation: {
      top_features: [
        { feature_name: 'Beacon Interval Variance', shap_value: 0.6 },
        { feature_name: 'Bytes Out', shap_value: 0.25 },
      ],
      base_value: 0.1,
      summary: 'Critical C2 anomaly detected. Consistent beaconing interval to a newly registered domain.',
    },
  },
  {
    id: 'ALT-20260801-003',
    source_module: 'anomaly',
    timestamp: new Date(Date.now() - 1000 * 60 * 120).toISOString(),
    severity: 'medium',
    mitre_technique_id: 'T1046',
    confidence_score: 0.72,
    explanation: {
      top_features: [
        { feature_name: 'Unique Ports Scanned', shap_value: 0.4 },
        { feature_name: 'Connection Rate', shap_value: 0.3 },
      ],
      base_value: 0.05,
      summary: 'Possible network reconnaissance. Source IP scanned 50+ unique internal ports in 2 minutes.',
    },
  },
];

export const mockPlaybookT1566: Playbook = {
  id: 'PB-T1566-001',
  mitre_technique_id: 'T1566',
  title: 'Phishing Email — Credential Harvest Response',
  severity_threshold: 'medium',
  estimated_response_time_minutes: 45,
  steps: [
    { action: 'Isolate reported email', description: 'Quarantine the email globally.', automatable: true },
    { action: 'Block sender domain', description: 'Add domain to blocklist.', automatable: true },
    { action: 'Force credential reset', description: 'Reset password for clicked users.', automatable: false },
    { action: 'Update threat intelligence', description: 'Add IOCs to TI platform.', automatable: true },
  ],
};

export const mockPlaybookT1071: Playbook = {
  id: 'PB-T1071-001',
  mitre_technique_id: 'T1071',
  title: 'C2 Communication — Application Layer Protocol',
  severity_threshold: 'high',
  estimated_response_time_minutes: 60,
  steps: [
    { action: 'Isolate compromised host', description: 'Move to quarantine VLAN.', automatable: true },
    { action: 'Block C2 destination', description: 'Block IP/Domain on firewall.', automatable: true },
    { action: 'Capture network forensics', description: 'Run full PCAP.', automatable: false },
  ],
};

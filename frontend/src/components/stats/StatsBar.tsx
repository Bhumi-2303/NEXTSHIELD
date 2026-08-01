import React from 'react';
import { Activity, AlertTriangle, ShieldAlert } from 'lucide-react';
import { ThreatAlert } from '../../lib/types';

interface StatsBarProps {
  alerts: ThreatAlert[];
}

export function StatsBar({ alerts }: StatsBarProps) {
  const total = alerts.length;
  const critical = alerts.filter(a => a.severity === 'critical').length;
  const phishing = alerts.filter(a => a.source_module === 'phishing').length;
  const anomaly = alerts.filter(a => a.source_module === 'anomaly').length;

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      <div className="bg-soc-panel border border-soc-border p-4 rounded-lg flex items-center justify-between">
        <div>
          <p className="text-soc-muted text-sm uppercase tracking-wider">Total Alerts (24h)</p>
          <p className="text-3xl font-bold mt-1 text-soc-text">{total}</p>
        </div>
        <Activity className="h-8 w-8 text-soc-muted opacity-50" />
      </div>
      
      <div className="bg-soc-panel border border-soc-border p-4 rounded-lg flex items-center justify-between">
        <div>
          <p className="text-soc-muted text-sm uppercase tracking-wider">Critical Severity</p>
          <p className="text-3xl font-bold mt-1 text-sev-critical">{critical}</p>
        </div>
        <AlertTriangle className="h-8 w-8 text-sev-critical opacity-50" />
      </div>

      <div className="bg-soc-panel border border-soc-border p-4 rounded-lg flex items-center justify-between">
        <div>
          <p className="text-soc-muted text-sm uppercase tracking-wider">Phishing Module</p>
          <p className="text-3xl font-bold mt-1 text-soc-text">{phishing}</p>
        </div>
        <ShieldAlert className="h-8 w-8 text-soc-muted opacity-50" />
      </div>

      <div className="bg-soc-panel border border-soc-border p-4 rounded-lg flex items-center justify-between">
        <div>
          <p className="text-soc-muted text-sm uppercase tracking-wider">Anomaly Module</p>
          <p className="text-3xl font-bold mt-1 text-soc-text">{anomaly}</p>
        </div>
        <Activity className="h-8 w-8 text-soc-muted opacity-50" />
      </div>
    </div>
  );
}

'use client';

import React from 'react';
import { useRouter } from 'next/navigation';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { ShieldAlert, X } from 'lucide-react';
import { ThreatAlert } from '../../lib/types';
import { format } from 'date-fns';

interface AlertDetailPanelProps {
  alert: ThreatAlert | null;
  onClose: () => void;
}

export function AlertDetailPanel({ alert, onClose }: AlertDetailPanelProps) {
  const router = useRouter();

  if (!alert) {
    return (
      <div className="h-full border-l border-soc-border bg-soc-panel/50 flex flex-col items-center justify-center p-8 text-center text-soc-muted">
        <ShieldAlert className="h-16 w-16 mb-4 opacity-20" />
        <p>Select an alert from the feed to view details and explanations.</p>
      </div>
    );
  }

  // Format data for Recharts
  const chartData = alert.explanation.features
    .map(f => ({
      name: f.feature_name,
      value: f.shap_value,
      isPositive: f.shap_value > 0
    }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value));

  const handleRespond = () => {
    router.push(`/dashboard/${alert.id}/respond`);
  };

  return (
    <div className="h-full border-l border-soc-border bg-soc-panel flex flex-col overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-soc-border flex items-start justify-between bg-soc-bg/50">
        <div>
          <h2 className="text-lg font-bold">Alert Details</h2>
          <p className="text-xs text-soc-muted font-mono mt-1">{alert.id}</p>
        </div>
        <button onClick={onClose} className="text-soc-muted hover:text-soc-text p-1">
          <X className="h-5 w-5" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-8">
        {/* Summary Section */}
        <section>
          <h3 className="text-sm font-bold text-soc-muted uppercase tracking-wider mb-3">Incident Summary</h3>
          <div className="bg-soc-bg border border-soc-border p-4 rounded text-sm leading-relaxed">
            {alert.explanation.summary}
          </div>
        </section>

        {/* SHAP Explanation Section */}
        <section>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-soc-muted uppercase tracking-wider">AI Explainability (SHAP)</h3>
            <span className="text-xs font-mono text-soc-muted">Base Value: {alert.explanation.base_value.toFixed(2)}</span>
          </div>
          <div className="bg-soc-bg border border-soc-border p-4 rounded h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" axisLine={false} tickLine={false} tick={{ fill: '#a1a1aa', fontSize: 12 }} width={120} />
                <Tooltip 
                  cursor={{ fill: '#27272a' }} 
                  contentStyle={{ backgroundColor: '#18181b', borderColor: '#27272a', color: '#e4e4e7' }}
                  formatter={(value: any) => [typeof value === 'number' ? value.toFixed(3) : value, 'SHAP Value']}
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={20}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.isPositive ? '#ef4444' : '#3b82f6'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <p className="text-xs text-soc-muted mt-2 text-center">
            <span className="text-sev-critical font-bold">Red</span> increases risk score, <span className="text-sev-low font-bold">Blue</span> decreases it.
          </p>
        </section>

        {/* Raw Payload Section (if available) */}
        {alert.raw_payload && (
          <section>
            <h3 className="text-sm font-bold text-soc-muted uppercase tracking-wider mb-3">Extracted Artifacts</h3>
            <pre className="bg-soc-bg border border-soc-border p-4 rounded text-xs font-mono overflow-x-auto text-soc-muted">
              {JSON.stringify(alert.raw_payload, null, 2)}
            </pre>
          </section>
        )}
      </div>

      {/* Action Footer */}
      <div className="p-4 border-t border-soc-border bg-soc-bg/50">
        <button 
          onClick={handleRespond}
          className="w-full bg-soc-text text-soc-bg hover:bg-white font-bold py-3 px-4 rounded transition-colors flex items-center justify-center gap-2"
        >
          <ShieldAlert className="h-5 w-5" />
          Respond with Playbook
        </button>
      </div>
    </div>
  );
}

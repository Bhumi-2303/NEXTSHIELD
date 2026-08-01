import React from 'react';
import { Mail, Activity, ArrowRight } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { ThreatAlert } from '../../lib/types';
import { cn } from '../../lib/utils';

interface AlertCardProps {
  alert: ThreatAlert;
  isSelected: boolean;
  onClick: () => void;
}

export function AlertCard({ alert, isSelected, onClick }: AlertCardProps) {
  const severityColors = {
    critical: 'bg-sev-critical/20 text-sev-critical border-sev-critical/50',
    high: 'bg-sev-high/20 text-sev-high border-sev-high/50',
    medium: 'bg-sev-medium/20 text-sev-medium border-sev-medium/50',
    low: 'bg-sev-low/20 text-sev-low border-sev-low/50',
  };

  const Icon = alert.source_module === 'phishing' ? Mail : Activity;

  return (
    <div
      onClick={onClick}
      className={cn(
        "bg-soc-panel border p-4 rounded-lg cursor-pointer transition-all hover:bg-soc-border hover:-translate-y-0.5 group",
        isSelected ? "border-soc-text" : "border-soc-border"
      )}
    >
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-3">
          <div className="bg-soc-border p-2 rounded-md">
            <Icon className="h-5 w-5 text-soc-text" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm text-soc-text font-bold uppercase">
                {alert.mitre_technique_id}
              </span>
              <span
                className={cn(
                  "text-[10px] uppercase font-bold px-2 py-0.5 rounded-full border",
                  severityColors[alert.severity]
                )}
              >
                {alert.severity}
              </span>
            </div>
            <p className="text-xs text-soc-muted mt-1">
              {formatDistanceToNow(new Date(alert.timestamp), { addSuffix: true })}
            </p>
          </div>
        </div>
        <div className="flex flex-col items-end">
          <span className="text-xs text-soc-muted uppercase">Confidence</span>
          <span className="font-mono text-lg font-bold">{(alert.confidence_score * 100).toFixed(0)}%</span>
        </div>
      </div>
      
      <p className="text-sm text-soc-text/80 line-clamp-2 mt-3">
        {alert.explanation.summary}
      </p>

      <div className="mt-4 flex items-center text-xs text-soc-muted group-hover:text-soc-text transition-colors">
        <span>View Details</span>
        <ArrowRight className="ml-1 h-3 w-3" />
      </div>
    </div>
  );
}

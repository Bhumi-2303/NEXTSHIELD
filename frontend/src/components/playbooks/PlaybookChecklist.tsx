import React from 'react';
import { Playbook, SimulationTimelineEntry } from '../../lib/types';
import { CheckCircle2, Clock, Circle, Bot, User } from 'lucide-react';
import { cn } from '../../lib/utils';

interface PlaybookChecklistProps {
  playbook: Playbook;
  timeline: SimulationTimelineEntry[] | null;
}

export function PlaybookChecklist({ playbook, timeline }: PlaybookChecklistProps) {
  return (
    <div className="space-y-4">
      {playbook.steps.map((step, idx) => {
        const stepNum = idx + 1;
        const timelineEntry = timeline?.find(t => t.step_number === stepNum);
        
        let status = 'pending';
        if (timelineEntry) {
          status = timelineEntry.status === 'completed' ? 'completed' : 'awaiting';
        }

        return (
          <div 
            key={idx}
            className={cn(
              "flex gap-4 p-4 rounded-lg border bg-soc-panel",
              status === 'completed' ? "border-soc-success/30" : "border-soc-border"
            )}
          >
            <div className="mt-0.5 flex-shrink-0">
              {status === 'completed' ? (
                <CheckCircle2 className="h-6 w-6 text-soc-success" />
              ) : status === 'awaiting' ? (
                <Clock className="h-6 w-6 text-sev-medium" />
              ) : (
                <Circle className="h-6 w-6 text-soc-muted" />
              )}
            </div>
            
            <div className="flex-1">
              <div className="flex items-center justify-between mb-1">
                <h4 className={cn(
                  "font-bold",
                  status === 'completed' ? "text-soc-success" : "text-soc-text"
                )}>
                  {stepNum}. {step.action}
                </h4>
                <div className="flex items-center gap-1 text-xs text-soc-muted bg-soc-bg px-2 py-0.5 rounded border border-soc-border">
                  {step.automatable ? <Bot className="h-3 w-3" /> : <User className="h-3 w-3" />}
                  {step.automatable ? 'AUTO' : 'MANUAL'}
                </div>
              </div>
              <p className="text-sm text-soc-muted">{step.description}</p>
              
              {timelineEntry && (
                <div className="mt-3 text-xs bg-soc-bg border border-soc-border p-2 rounded text-soc-text font-mono flex justify-between">
                  <span>{timelineEntry.result}</span>
                  {timelineEntry.duration_seconds && (
                    <span className="text-soc-muted">{timelineEntry.duration_seconds.toFixed(2)}s</span>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

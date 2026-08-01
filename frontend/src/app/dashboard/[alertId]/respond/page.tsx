'use client';

import React, { useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, ShieldAlert } from 'lucide-react';
import { ThreatAlert, Playbook, SimulationResult } from '../../../../lib/types';
import { fetchAlerts, fetchPlaybookForAlert, simulatePlaybook } from '../../../../lib/api';
import { PlaybookChecklist } from '../../../../components/playbooks/PlaybookChecklist';
import { SimulateButton } from '../../../../components/playbooks/SimulateButton';

export default function RespondPage() {
  const params = useParams();
  const router = useRouter();
  const alertId = params.alertId as string;

  const [alert, setAlert] = useState<ThreatAlert | null>(null);
  const [playbook, setPlaybook] = useState<Playbook | null>(null);
  const [simulation, setSimulation] = useState<SimulationResult | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);

  useEffect(() => {
    async function loadData() {
      // In a real app, we'd fetch the specific alert by ID.
      // Here we fetch all and find it.
      const alerts = await fetchAlerts();
      const foundAlert = alerts.find(a => a.id === alertId);
      if (foundAlert) {
        setAlert(foundAlert);
        const pb = await fetchPlaybookForAlert(foundAlert.mitre_technique_id);
        setPlaybook(pb);
      }
    }
    loadData();
  }, [alertId]);

  const handleSimulate = async () => {
    if (!alert || !playbook) return;
    setIsSimulating(true);
    try {
      const result = await simulatePlaybook(alert.mitre_technique_id, alert.severity);
      
      // Animate the timeline steps one by one for demo effect
      setSimulation({ ...result, timeline: [] });
      
      for (let i = 0; i < result.timeline.length; i++) {
        await new Promise(resolve => setTimeout(resolve, 800)); // Demo animation delay
        setSimulation(prev => {
          if (!prev) return prev;
          return {
            ...prev,
            timeline: [...prev.timeline, result.timeline[i]]
          };
        });
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsSimulating(false);
    }
  };

  if (!alert || !playbook) {
    return <div className="p-8 text-soc-muted">Loading incident context...</div>;
  }

  return (
    <div className="min-h-screen bg-soc-bg text-soc-text pb-12">
      {/* Header */}
      <header className="h-16 border-b border-soc-border bg-soc-panel flex items-center px-6 sticky top-0 z-10">
        <button 
          onClick={() => router.push('/')}
          className="mr-6 text-soc-muted hover:text-soc-text flex items-center gap-2 text-sm transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Dashboard
        </button>
        <ShieldAlert className="h-5 w-5 text-sev-critical mr-3" />
        <h1 className="font-bold">Incident Response: {alert.id}</h1>
      </header>

      <main className="max-w-4xl mx-auto mt-8 px-6">
        {/* Context Panel */}
        <div className="bg-soc-panel border border-soc-border rounded-lg p-6 mb-8 flex items-start justify-between">
          <div>
            <h2 className="text-soc-muted text-sm uppercase tracking-wider mb-2">Selected Playbook</h2>
            <p className="text-xl font-bold text-soc-text mb-1">{playbook.title}</p>
            <p className="text-sm text-soc-muted font-mono">{playbook.id} • {playbook.mitre_technique_id}</p>
          </div>
          <div className="text-right">
            <h2 className="text-soc-muted text-sm uppercase tracking-wider mb-2">Est. Resolution</h2>
            <p className="text-xl font-bold text-soc-text">{playbook.estimated_response_time_minutes} min</p>
          </div>
        </div>

        {/* Action Bar */}
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-bold">Response Steps</h2>
          <SimulateButton 
            onSimulate={handleSimulate} 
            isSimulating={isSimulating} 
            hasSimulated={simulation?.timeline.length === playbook.steps.length} 
          />
        </div>

        {/* Checklist */}
        <PlaybookChecklist 
          playbook={playbook} 
          timeline={simulation?.timeline || null} 
        />
        
        {simulation?.timeline.length === playbook.steps.length && (
          <div className="mt-8 p-4 bg-soc-success/10 border border-soc-success/30 rounded-lg flex items-center gap-3 text-soc-success">
            <ShieldAlert className="h-5 w-5" />
            <p className="font-bold">Simulation complete. In a real scenario, this would have contained the threat automatically.</p>
          </div>
        )}
      </main>
    </div>
  );
}

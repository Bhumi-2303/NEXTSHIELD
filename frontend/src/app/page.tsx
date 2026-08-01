'use client';

import React, { useState } from 'react';
import { ThreatAlert } from '../lib/types';
import { AlertFeed } from '../components/alerts/AlertFeed';
import { AlertDetailPanel } from '../components/alerts/AlertDetailPanel';
import { StatsBar } from '../components/stats/StatsBar';
import { Shield } from 'lucide-react';

export default function Dashboard() {
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);

  return (
    <div className="flex flex-col h-screen bg-soc-bg overflow-hidden">
      {/* Top Navigation */}
      <header className="h-14 border-b border-soc-border flex items-center px-6 bg-soc-panel shrink-0">
        <Shield className="h-6 w-6 text-soc-text mr-3" />
        <h1 className="font-bold tracking-widest uppercase text-soc-text text-sm">
          NEXTSHIELD <span className="text-soc-muted">SOC</span>
        </h1>
        <div className="ml-auto text-xs font-mono text-soc-muted bg-soc-bg px-2 py-1 rounded border border-soc-border">
          STATUS: ONLINE
        </div>
      </header>

      {/* Main Content Area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Column: Alerts Feed & Stats */}
        <div className="flex-1 flex flex-col min-w-0">
          <div className="p-6 pb-2 shrink-0">
            <StatsBar alerts={alerts} />
            <h2 className="text-sm font-bold text-soc-muted uppercase tracking-wider mb-4">
              Live Threat Feed
            </h2>
          </div>
          <div className="flex-1 overflow-y-auto px-6 pb-6">
            <AlertFeed 
              onSelectAlert={setSelectedAlert}
              selectedAlertId={selectedAlert?.id ?? null}
              onAlertsLoaded={setAlerts}
            />
          </div>
        </div>

        {/* Right Column: Alert Detail Slide-out */}
        <div 
          className="w-[450px] shrink-0 transition-all duration-300 ease-in-out"
          style={{
            marginRight: selectedAlert ? '0' : '-450px',
            opacity: selectedAlert ? 1 : 0
          }}
        >
          <AlertDetailPanel 
            alert={selectedAlert} 
            onClose={() => setSelectedAlert(null)} 
          />
        </div>
      </div>
    </div>
  );
}

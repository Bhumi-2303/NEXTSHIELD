'use client';

import React, { useEffect, useState } from 'react';
import { ThreatAlert } from '../../lib/types';
import { fetchAlerts } from '../../lib/api';
import { AlertCard } from './AlertCard';
import { Loader2 } from 'lucide-react';

interface AlertFeedProps {
  onSelectAlert: (alert: ThreatAlert) => void;
  selectedAlertId: string | null;
  onAlertsLoaded?: (alerts: ThreatAlert[]) => void;
}

export function AlertFeed({ onSelectAlert, selectedAlertId, onAlertsLoaded }: AlertFeedProps) {
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    
    const loadData = async () => {
      try {
        const data = await fetchAlerts();
        if (mounted) {
          setAlerts(data);
          setLoading(false);
          if (onAlertsLoaded) onAlertsLoaded(data);
        }
      } catch (err) {
        console.error("Failed to fetch alerts", err);
        if (mounted) setLoading(false);
      }
    };

    loadData();
    // Poll every 10 seconds
    const interval = setInterval(loadData, 10000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [onAlertsLoaded]);

  if (loading && alerts.length === 0) {
    return (
      <div className="flex justify-center items-center h-64">
        <Loader2 className="h-8 w-8 animate-spin text-soc-muted" />
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {alerts.map(alert => (
        <AlertCard 
          key={alert.id}
          alert={alert}
          isSelected={alert.id === selectedAlertId}
          onClick={() => onSelectAlert(alert)}
        />
      ))}
      
      {alerts.length === 0 && (
        <div className="text-center p-8 border border-dashed border-soc-border rounded-lg text-soc-muted">
          No active threats detected.
        </div>
      )}
    </div>
  );
}

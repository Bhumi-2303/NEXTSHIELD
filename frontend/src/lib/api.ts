import { ThreatAlert, Playbook, SimulationResult } from './types';
import { mockAlerts, mockPlaybookT1566, mockPlaybookT1071 } from './mockData';

const USE_MOCK_DATA = false;
const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const API_BASE = `${baseUrl.replace(/\/$/, '')}/api/v1`;

export async function fetchAlerts(): Promise<ThreatAlert[]> {
  if (USE_MOCK_DATA) {
    // Simulate network delay
    await new Promise((resolve) => setTimeout(resolve, 500));
    return mockAlerts;
  }

  const res = await fetch(`${API_BASE}/alerts`); // Assuming such an endpoint exists or will exist
  if (!res.ok) throw new Error('Failed to fetch alerts');
  return res.json();
}

export async function fetchPlaybookForAlert(mitreTechniqueId: string): Promise<Playbook> {
  if (USE_MOCK_DATA) {
    await new Promise((resolve) => setTimeout(resolve, 300));
    if (mitreTechniqueId === 'T1566') return mockPlaybookT1566;
    if (mitreTechniqueId === 'T1071') return mockPlaybookT1071;
    // Fallback
    return mockPlaybookT1566;
  }


  // Note: The actual endpoint returns a simulation result, not the playbook itself.
  // Wait, if we want just the playbook to show steps, we need GET /playbooks/by-technique.
  // We'll use the first matched for now.
  const listRes = await fetch(`${API_BASE}/playbooks/by-technique/${mitreTechniqueId}`);
  if (!listRes.ok) throw new Error('Failed to fetch playbook');
  const playbooks: Playbook[] = await listRes.json();
  return playbooks[0]; 
}

export async function simulatePlaybook(mitreTechniqueId: string, severity: string): Promise<SimulationResult> {
  if (USE_MOCK_DATA) {
    await new Promise((resolve) => setTimeout(resolve, 600));
    const pb = mitreTechniqueId === 'T1566' ? mockPlaybookT1566 : mockPlaybookT1071;
    let cursor = new Date();
    
    return {
      playbook_id: pb.id,
      playbook_title: pb.title,
      mitre_technique_id: pb.mitre_technique_id,
      simulation_started_at: cursor.toISOString(),
      total_steps: pb.steps.length,
      automated_steps_completed: pb.steps.filter(s => s.automatable).length,
      manual_steps_pending: pb.steps.filter(s => !s.automatable).length,
      estimated_response_time_minutes: pb.estimated_response_time_minutes,
      timeline: pb.steps.map((step, i) => {
        const execSecs = step.automatable ? Math.random() * 5 + 1 : null;
        if (execSecs) cursor = new Date(cursor.getTime() + execSecs * 1000);
        return {
          step_number: i + 1,
          action: step.action,
          automatable: step.automatable,
          status: step.automatable ? 'completed' : 'pending_human_action',
          executed_at: step.automatable ? cursor.toISOString() : null,
          duration_seconds: execSecs,
          result: step.automatable ? `Auto-executed successfully: ${step.action}` : 'Awaiting human action',
        };
      })
    };
  }

  const res = await fetch(`${API_BASE}/playbooks/simulate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mitre_technique_id: mitreTechniqueId, severity }),
  });
  if (!res.ok) throw new Error('Failed to simulate playbook');
  return res.json();
}

import React from 'react';
import { Play, Loader2 } from 'lucide-react';
import { cn } from '../../lib/utils';

interface SimulateButtonProps {
  onSimulate: () => void;
  isSimulating: boolean;
  hasSimulated: boolean;
}

export function SimulateButton({ onSimulate, isSimulating, hasSimulated }: SimulateButtonProps) {
  return (
    <button
      onClick={onSimulate}
      disabled={isSimulating || hasSimulated}
      className={cn(
        "flex items-center gap-2 px-6 py-3 rounded font-bold transition-all",
        hasSimulated 
          ? "bg-soc-border text-soc-muted cursor-not-allowed"
          : "bg-sev-critical hover:bg-red-600 text-white"
      )}
    >
      {isSimulating ? (
        <>
          <Loader2 className="h-5 w-5 animate-spin" />
          Simulating Response...
        </>
      ) : hasSimulated ? (
        <>Simulation Complete</>
      ) : (
        <>
          <Play className="h-5 w-5 fill-current" />
          Simulate Auto-Response
        </>
      )}
    </button>
  );
}

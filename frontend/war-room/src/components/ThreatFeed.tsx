/**
 * ThreatFeed Component
 * ====================
 * 
 * Displays real-time threat feed using useRealtimeFeed hook.
 * Shows SCAN and THREAT messages in a scrolling list.
 */

import React, { useMemo } from 'react';
import { AlertTriangle, Shield, Activity } from 'lucide-react';
import { useRealtimeFeed, ThreatMessage } from '../hooks/useRealtimeFeed';

const ThreatFeed: React.FC = () => {
  const { messages, isConnected } = useRealtimeFeed();

  const threatCount = useMemo(() => {
    return messages.filter(m => m.type === 'THREAT' || m.status === 'MALICIOUS').length;
  }, [messages]);

  const formatTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString();
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'MALICIOUS':
        return 'text-red-400 border-red-500';
      case 'Simulating...':
        return 'text-yellow-400 border-yellow-500';
      default:
        return 'text-green-400 border-green-500';
    }
  };

  const getRiskColor = (riskScore: number) => {
    if (riskScore >= 0.8) return 'bg-red-500';
    if (riskScore >= 0.5) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="mb-4 flex items-center justify-between border-b border-border pb-2">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-primary" />
          <span className="text-sm font-semibold text-foreground">Threat Feed</span>
        </div>
        <div className="flex items-center gap-2">
          <div className={`h-2 w-2 rounded-full ${isConnected ? 'bg-neon-green' : 'bg-red-500'}`} />
          <span className="text-xs text-muted-foreground">
            {isConnected ? 'Live' : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Stats */}
      <div className="mb-4 grid grid-cols-2 gap-2">
        <div className="rounded-md border border-border bg-card/50 p-2">
          <div className="text-xs text-muted-foreground">Total Scans</div>
          <div className="text-lg font-bold text-foreground">{messages.length}</div>
        </div>
        <div className="rounded-md border border-border bg-card/50 p-2">
          <div className="text-xs text-muted-foreground">Threats</div>
          <div className="text-lg font-bold text-red-400">{threatCount}</div>
        </div>
      </div>

      {/* Feed List */}
      <div className="flex-1 space-y-2 overflow-y-auto">
        {messages.length === 0 ? (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
            <div className="text-center">
              <Activity className="mx-auto mb-2 h-8 w-8 animate-pulse" />
              <div>Waiting for events...</div>
            </div>
          </div>
        ) : (
          messages.map((message, index) => (
            <div
              key={`${message.tx_hash}-${message.timestamp}-${index}`}
              className={`rounded-md border ${getStatusColor(message.status)} bg-card/30 p-3 transition-all hover:bg-card/50`}
            >
              <div className="mb-2 flex items-start justify-between">
                <div className="flex items-center gap-2">
                  {message.type === 'THREAT' || message.status === 'MALICIOUS' ? (
                    <AlertTriangle className="h-4 w-4 text-red-400" />
                  ) : (
                    <Shield className="h-4 w-4 text-green-400" />
                  )}
                  <span className="text-xs font-mono text-foreground">
                    {message.tx_hash.slice(0, 10)}...
                  </span>
                </div>
                <span className="text-xs text-muted-foreground">
                  {formatTime(message.timestamp)}
                </span>
              </div>

              <div className="mb-2 text-xs text-foreground">
                <div className="mb-1">
                  <span className="text-muted-foreground">Chain: </span>
                  <span className="font-medium capitalize">{message.source_chain}</span>
                </div>
                {message.contract && (
                  <div className="mb-1">
                    <span className="text-muted-foreground">Contract: </span>
                    <span className="font-mono text-xs">{message.contract.slice(0, 8)}...</span>
                  </div>
                )}
                {message.details?.protocol && (
                  <div className="mb-1">
                    <span className="text-muted-foreground">Protocol: </span>
                    <span className="font-medium">{message.details.protocol}</span>
                  </div>
                )}
              </div>

              {/* Risk Score Bar */}
              <div className="flex items-center gap-2">
                <div className="flex-1 overflow-hidden rounded-full bg-secondary">
                  <div
                    className={`h-1.5 transition-all duration-300 ${getRiskColor(message.risk_score)}`}
                    style={{ width: `${message.risk_score * 100}%` }}
                  />
                </div>
                <span className="text-xs font-mono text-muted-foreground">
                  {(message.risk_score * 100).toFixed(0)}%
                </span>
              </div>

              {/* Threat Details */}
              {message.details?.predicted_type && (
                <div className="mt-2 rounded border border-border bg-secondary/30 px-2 py-1 text-xs">
                  <div className="font-medium text-foreground">
                    {message.details.predicted_type.replace(/_/g, ' ')}
                  </div>
                  {message.details.severity && (
                    <div className="text-muted-foreground">
                      Severity: {message.details.severity}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export { ThreatFeed };
export default ThreatFeed;

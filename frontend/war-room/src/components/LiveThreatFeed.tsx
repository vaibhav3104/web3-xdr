/**
 * Live Threat Feed Component
 * ===========================
 * 
 * Matrix-style terminal feed showing real-time transaction scans.
 * - Green: Safe transactions (fade quickly)
 * - Yellow: Suspicious (stay longer)
 * - Red: Confirmed threats (freeze feed, expand details)
 */

import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface ThreatMessage {
  type: 'SCAN' | 'THREAT';
  timestamp: number;
  source_chain: string;
  tx_hash: string;
  contract: string;
  risk_score: number;
  status: 'Safe' | 'Simulating...' | 'MALICIOUS';
  details?: any;
}

interface LiveThreatFeedProps {
  messages: ThreatMessage[];
  maxItems?: number;
}

const LiveThreatFeed: React.FC<LiveThreatFeedProps> = ({ messages, maxItems = 50 }) => {
  const [expandedThreat, setExpandedThreat] = useState<string | null>(null);
  const feedRef = useRef<HTMLDivElement>(null);

  // Limit messages to maxItems
  const displayedMessages = useMemo(() => {
    return messages.slice(-maxItems);
  }, [messages, maxItems]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, [displayedMessages]);

  const getStatusColor = (status: string, riskScore: number): string => {
    if (status === 'MALICIOUS') return 'text-red-500';
    if (status === 'Simulating...') return 'text-yellow-500';
    if (riskScore > 0.5) return 'text-yellow-400';
    return 'text-green-400';
  };

  const getGlowEffect = (status: string, riskScore: number): string => {
    if (status === 'MALICIOUS') return 'shadow-[0_0_20px_rgba(255,0,0,0.8)]';
    if (status === 'Simulating...') return 'shadow-[0_0_15px_rgba(255,255,0,0.6)]';
    if (riskScore > 0.5) return 'shadow-[0_0_10px_rgba(255,255,0,0.4)]';
    return '';
  };

  const formatTime = (timestamp: number): string => {
    return new Date(timestamp * 1000).toLocaleTimeString();
  };

  const shortenHash = (hash: string): string => {
    return `${hash.slice(0, 6)}...${hash.slice(-4)}`;
  };

  return (
    <div className="h-full flex flex-col bg-black border border-green-500 rounded-lg overflow-hidden">
      {/* Header */}
      <div className="px-4 py-2 bg-green-900/30 border-b border-green-500">
        <h2 className="text-green-400 font-mono text-sm font-bold">LIVE THREAT FEED</h2>
      </div>

      {/* Feed Container */}
      <div
        ref={feedRef}
        className="flex-1 overflow-y-auto p-4 space-y-1 font-mono text-xs"
        style={{ scrollbarWidth: 'thin', scrollbarColor: '#00ff00 #000000' }}
      >
        <AnimatePresence initial={false}>
          {displayedMessages.map((msg, index) => {
            const isThreat = msg.type === 'THREAT' || msg.status === 'MALICIOUS';
            const isExpanded = expandedThreat === msg.tx_hash;

            return (
              <motion.div
                key={`${msg.tx_hash}-${msg.timestamp}-${index}`}
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, x: -100 }}
                transition={{ duration: 0.3 }}
                className={`
                  p-2 rounded border-l-2 cursor-pointer
                  ${getStatusColor(msg.status, msg.risk_score)}
                  ${getGlowEffect(msg.status, msg.risk_score)}
                  ${isThreat ? 'border-l-4' : 'border-l-2'}
                  ${isThreat ? 'bg-red-900/20' : 'bg-green-900/10'}
                  hover:bg-green-900/30
                `}
                onClick={() => isThreat && setExpandedThreat(isExpanded ? null : msg.tx_hash)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-gray-500">[{formatTime(msg.timestamp)}]</span>
                    <span className="font-bold">{msg.status}</span>
                    <span className="text-gray-400">→</span>
                    <span className="text-blue-400">{msg.source_chain}</span>
                  </div>
                  <span className="text-gray-500">{shortenHash(msg.tx_hash)}</span>
                </div>

                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="mt-2 pt-2 border-t border-red-500/50"
                  >
                    <div className="space-y-1 text-xs">
                      <div><span className="text-gray-500">Contract:</span> {msg.contract}</div>
                      <div><span className="text-gray-500">Risk Score:</span> {(msg.risk_score * 100).toFixed(1)}%</div>
                      {msg.details && (
                        <div><span className="text-gray-500">Details:</span> {JSON.stringify(msg.details, null, 2)}</div>
                      )}
                    </div>
                  </motion.div>
                )}
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>

      {/* Footer */}
      <div className="px-4 py-1 bg-green-900/20 border-t border-green-500 text-green-400 text-xs font-mono">
        {displayedMessages.length} messages | {messages.filter(m => m.type === 'THREAT').length} threats
      </div>
    </div>
  );
};

export default LiveThreatFeed;


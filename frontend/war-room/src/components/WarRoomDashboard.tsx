/**
 * War Room Dashboard - Main Container
 * ====================================
 * 
 * Main dashboard component that orchestrates all sub-components.
 * - Dark mode theme (Black bg, Neon Green/Red accents)
 * - Layout: Feed left, Graph center, Metrics right
 * - WebSocket connection management
 * - Demo mode support
 */

import React, { useState, useMemo } from 'react';
import LiveThreatFeed from './LiveThreatFeed';
import CrossChainGraph from './CrossChainGraph';
import MetricCards from './MetricCards';
import ROICard from './ROICard';
import { useWebSocket } from '../hooks/useWebSocket';
import { isDemoMode } from './DemoMode';
import { motion } from 'framer-motion';

const WarRoomDashboard: React.FC = () => {
  const { messages, connectionStatus, isConnected, isDemo } = useWebSocket();
  const [showDemoWarning, setShowDemoWarning] = useState(isDemoMode());

  // Filter messages by type for different components
  const threatMessages = useMemo(() => {
    return messages.filter(m => m.type === 'SCAN' || m.type === 'THREAT');
  }, [messages]);

  return (
    <div className="h-screen w-screen bg-black text-green-400 overflow-hidden">
      {/* Header */}
      <header className="h-16 bg-black border-b-2 border-green-500 flex items-center justify-between px-6">
        <div className="flex items-center gap-4">
          <h1 className="text-2xl font-mono font-bold text-green-400">
            SENTINEL3 WAR ROOM
          </h1>
          <div className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'} animate-pulse`} />
            <span className="text-xs text-gray-400">{connectionStatus}</span>
          </div>
        </div>
        
        {/* ROI Card in Header */}
        <div className="w-64">
          <ROICard />
        </div>
        
        {isDemo && (
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-yellow-900/50 border border-yellow-500 px-4 py-2 rounded"
          >
            <span className="text-yellow-400 font-mono text-sm">DEMO MODE</span>
          </motion.div>
        )}

        {showDemoWarning && !isDemo && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="bg-blue-900/50 border border-blue-500 px-4 py-2 rounded cursor-pointer"
            onClick={() => window.location.href = window.location.href + '?demo=true'}
          >
            <span className="text-blue-400 font-mono text-xs">Enable Demo Mode</span>
          </motion.div>
        )}
      </header>

      {/* Main Content Grid */}
      <div className="h-[calc(100vh-4rem)] grid grid-cols-12 gap-4 p-4">
        {/* Left: Live Threat Feed */}
        <div className="col-span-4">
          <LiveThreatFeed messages={threatMessages} maxItems={50} />
        </div>

        {/* Center: Cross-Chain Graph */}
        <div className="col-span-5">
          <CrossChainGraph messages={threatMessages} />
        </div>

        {/* Right: Metrics */}
        <div className="col-span-3">
          <MetricCards messages={threatMessages} />
        </div>
      </div>

      {/* Footer */}
      <footer className="h-12 bg-black border-t-2 border-green-500 flex items-center justify-between px-6">
        <div className="text-xs text-gray-500 font-mono">
          Real-time threat detection • Zero-block protection • Cross-chain correlation
        </div>
        <div className="text-xs text-gray-500 font-mono">
          {new Date().toLocaleTimeString()}
        </div>
      </footer>

      {/* Guardian Triggered Animation */}
      {messages.some(m => m.type === 'GUARDIAN') && (
        <motion.div
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.5 }}
          className="fixed inset-0 flex items-center justify-center bg-black/90 z-50"
        >
          <motion.div
            initial={{ rotate: -180 }}
            animate={{ rotate: 0 }}
            transition={{ duration: 0.5 }}
            className="text-center"
          >
            <div className="text-8xl mb-4">🛡️</div>
            <h2 className="text-6xl font-mono font-bold text-red-500 mb-4">
              GUARDIAN TRIGGERED
            </h2>
            <p className="text-2xl text-green-400 font-mono">
              Contract paused • Threat neutralized
            </p>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
};

export default WarRoomDashboard;


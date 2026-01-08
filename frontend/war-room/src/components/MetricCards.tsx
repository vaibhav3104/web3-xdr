/**
 * Metric Cards Component
 * =====================
 * 
 * Tremor-based metric cards showing key statistics.
 * - Intents Scanned (24h) - Counter animation
 * - Zero-Day Blocks - Attacks stopped before mining
 * - Active Threats - Current threat count
 * - Cross-Chain Attacks Detected - Total count
 */

import React, { useMemo } from 'react';
import { Card, Metric, Text, BadgeDelta, Flex, Grid } from '@tremor/react';
import { motion } from 'framer-motion';

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

interface MetricCardsProps {
  messages: ThreatMessage[];
}

const MetricCards: React.FC<MetricCardsProps> = ({ messages }) => {
  // Calculate metrics
  const metrics = useMemo(() => {
    const now = Math.floor(Date.now() / 1000);
    const twentyFourHoursAgo = now - 86400;

    const recentMessages = messages.filter(m => m.timestamp >= twentyFourHoursAgo);
    const scans = recentMessages.filter(m => m.type === 'SCAN');
    const threats = messages.filter(m => m.type === 'THREAT' || m.status === 'MALICIOUS');
    const activeThreats = threats.filter(t => {
      const age = now - t.timestamp;
      return age < 3600; // Active if less than 1 hour old
    });
    const crossChainThreats = threats.filter(t => 
      t.details?.target_chain || t.details?.cross_chain === true
    );

    return {
      intentsScanned: scans.length,
      zeroDayBlocks: threats.filter(t => t.details?.zero_day === true).length,
      activeThreats: activeThreats.length,
      crossChainAttacks: crossChainThreats.length,
    };
  }, [messages]);

  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0 },
  };

  return (
    <div className="space-y-4">
      <div className="px-4 py-2 bg-green-900/30 border-b border-green-500 rounded-t-lg">
        <h2 className="text-green-400 font-mono text-sm font-bold">METRICS</h2>
      </div>
      <div className="p-4 space-y-4">
        <Grid numItems={1} className="gap-4">
          {/* Intents Scanned */}
          <motion.div
            variants={cardVariants}
            initial="hidden"
            animate="visible"
            transition={{ duration: 0.3 }}
          >
            <Card className="bg-black border border-green-500">
              <Flex alignItems="start">
                <div className="flex-1">
                  <Text className="text-gray-400 text-xs">Intents Scanned (24h)</Text>
                  <Metric className="text-green-400 font-mono">
                    {metrics.intentsScanned.toLocaleString()}
                  </Metric>
                </div>
                <BadgeDelta deltaType="moderateIncrease" className="bg-green-900/50">
                  Live
                </BadgeDelta>
              </Flex>
            </Card>
          </motion.div>

          {/* Zero-Day Blocks */}
          <motion.div
            variants={cardVariants}
            initial="hidden"
            animate="visible"
            transition={{ duration: 0.4 }}
          >
            <Card className="bg-black border border-yellow-500">
              <Flex alignItems="start">
                <div className="flex-1">
                  <Text className="text-gray-400 text-xs">Zero-Day Blocks</Text>
                  <Metric className="text-yellow-400 font-mono">
                    {metrics.zeroDayBlocks}
                  </Metric>
                  <Text className="text-gray-500 text-xs mt-1">
                    Attacks stopped before mining
                  </Text>
                </div>
                <BadgeDelta deltaType="moderateIncrease" className="bg-yellow-900/50">
                  {metrics.zeroDayBlocks > 0 ? 'Active' : 'None'}
                </BadgeDelta>
              </Flex>
            </Card>
          </motion.div>

          {/* Active Threats */}
          <motion.div
            variants={cardVariants}
            initial="hidden"
            animate="visible"
            transition={{ duration: 0.5 }}
          >
            <Card className={`bg-black border ${metrics.activeThreats > 0 ? 'border-red-500' : 'border-green-500'}`}>
              <Flex alignItems="start">
                <div className="flex-1">
                  <Text className="text-gray-400 text-xs">Active Threats</Text>
                  <Metric className={`font-mono ${metrics.activeThreats > 0 ? 'text-red-400' : 'text-green-400'}`}>
                    {metrics.activeThreats}
                  </Metric>
                  <Text className="text-gray-500 text-xs mt-1">
                    Detected in last hour
                  </Text>
                </div>
                <BadgeDelta 
                  deltaType={metrics.activeThreats > 0 ? "moderateIncrease" : "unchanged"}
                  className={metrics.activeThreats > 0 ? 'bg-red-900/50' : 'bg-green-900/50'}
                >
                  {metrics.activeThreats > 0 ? 'Alert' : 'Clear'}
                </BadgeDelta>
              </Flex>
            </Card>
          </motion.div>

          {/* Cross-Chain Attacks */}
          <motion.div
            variants={cardVariants}
            initial="hidden"
            animate="visible"
            transition={{ duration: 0.6 }}
          >
            <Card className="bg-black border border-purple-500">
              <Flex alignItems="start">
                <div className="flex-1">
                  <Text className="text-gray-400 text-xs">Cross-Chain Attacks</Text>
                  <Metric className="text-purple-400 font-mono">
                    {metrics.crossChainAttacks}
                  </Metric>
                  <Text className="text-gray-500 text-xs mt-1">
                    Multi-chain exploits detected
                  </Text>
                </div>
                <BadgeDelta deltaType="moderateIncrease" className="bg-purple-900/50">
                  Total
                </BadgeDelta>
              </Flex>
            </Card>
          </motion.div>
        </Grid>
      </div>
    </div>
  );
};

export default MetricCards;


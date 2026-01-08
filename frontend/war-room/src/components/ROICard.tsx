/**
 * ROI Card Component
 * ==================
 * 
 * Displays total saved capital and profit chart.
 * Shows cumulative saved value over time.
 */

import React, { useEffect, useState } from 'react';
import { Card, Metric, Text, BadgeDelta, LineChart, AreaChart } from '@tremor/react';
import { motion } from 'framer-motion';

interface ScorecardData {
  total_saved_usd: number;
  incidents_blocked: number;
  avg_reaction_time_ms: number;
  top_save: {
    name: string;
    amount: number;
    date: string;
  } | null;
  timeframe_hours: number;
}

interface ROICardProps {
  apiUrl?: string;
}

const ROICard: React.FC<ROICardProps> = ({ apiUrl = '/api/stats/scorecard' }) => {
  const [scorecard, setScorecard] = useState<ScorecardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [chartData, setChartData] = useState<Array<{ date: string; saved: number }>>([]);

  useEffect(() => {
    const fetchScorecard = async () => {
      try {
        const response = await fetch(`${apiUrl}?timeframe_hours=24`);
        if (!response.ok) {
          throw new Error('Failed to fetch scorecard');
        }
        const data = await response.json();
        setScorecard(data);
        
        // Generate chart data (cumulative over time)
        // In real implementation, would fetch historical data
        const mockData = [
          { date: '00:00', saved: data.total_saved_usd * 0.2 },
          { date: '06:00', saved: data.total_saved_usd * 0.4 },
          { date: '12:00', saved: data.total_saved_usd * 0.7 },
          { date: '18:00', saved: data.total_saved_usd * 0.9 },
          { date: '24:00', saved: data.total_saved_usd },
        ];
        setChartData(mockData);
        
        setLoading(false);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error');
        setLoading(false);
      }
    };

    fetchScorecard();
    // Refresh every 30 seconds
    const interval = setInterval(fetchScorecard, 30000);
    return () => clearInterval(interval);
  }, [apiUrl]);

  if (loading) {
    return (
      <Card className="bg-black border border-green-500">
        <Text className="text-gray-400">Loading ROI metrics...</Text>
      </Card>
    );
  }

  if (error || !scorecard) {
    return (
      <Card className="bg-black border border-red-500">
        <Text className="text-red-400">Error loading ROI metrics</Text>
      </Card>
    );
  }

  const formatCurrency = (amount: number): string => {
    if (amount >= 1_000_000) {
      return `$${(amount / 1_000_000).toFixed(2)}M`;
    }
    if (amount >= 1_000) {
      return `$${(amount / 1_000).toFixed(2)}K`;
    }
    return `$${amount.toFixed(2)}`;
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3 }}
    >
      <Card className="bg-black border-2 border-green-500">
        <div className="space-y-4">
          {/* Header */}
          <div className="flex items-center justify-between">
            <Text className="text-gray-400 text-xs font-mono">ROI SCORECARD</Text>
            <BadgeDelta deltaType="moderateIncrease" className="bg-green-900/50">
              Live
            </BadgeDelta>
          </div>

          {/* Total Saved */}
          <div>
            <Text className="text-gray-400 text-xs mb-1">Total Saved (24h)</Text>
            <Metric className="text-green-400 font-mono text-4xl">
              {formatCurrency(scorecard.total_saved_usd)}
            </Metric>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Text className="text-gray-500 text-xs">Incidents Blocked</Text>
              <Text className="text-green-400 font-mono text-lg">
                {scorecard.incidents_blocked}
              </Text>
            </div>
            <div>
              <Text className="text-gray-500 text-xs">Avg Reaction</Text>
              <Text className="text-yellow-400 font-mono text-lg">
                {scorecard.avg_reaction_time_ms.toFixed(0)}ms
              </Text>
            </div>
          </div>

          {/* Profit Chart */}
          {chartData.length > 0 && (
            <div className="mt-4">
              <Text className="text-gray-400 text-xs mb-2">Cumulative Saved</Text>
              <AreaChart
                data={chartData}
                index="date"
                categories={["saved"]}
                colors={["green"]}
                showLegend={false}
                showGridLines={false}
                className="h-24"
                valueFormatter={(value) => formatCurrency(value)}
              />
            </div>
          )}

          {/* Top Save */}
          {scorecard.top_save && (
            <div className="mt-4 pt-4 border-t border-green-500/50">
              <Text className="text-gray-400 text-xs mb-1">Top Save</Text>
              <Text className="text-green-400 font-mono text-sm">
                {scorecard.top_save.name}
              </Text>
              <Text className="text-yellow-400 font-mono text-lg">
                {formatCurrency(scorecard.top_save.amount)}
              </Text>
            </div>
          )}
        </div>
      </Card>
    </motion.div>
  );
};

export default ROICard;


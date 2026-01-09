/**
 * KPICard Component
 * =================
 * 
 * Displays a KPI metric card with icon, value, and change indicator.
 */

import React from 'react';
import { LucideIcon } from 'lucide-react';

export interface KPICardProps {
  title: string;
  value: string;
  change?: string;
  changeType?: 'positive' | 'negative' | 'neutral';
  icon: LucideIcon;
  accentColor?: 'green' | 'red' | 'cyan' | 'yellow' | 'blue';
}

const KPICard: React.FC<KPICardProps> = ({
  title,
  value,
  change,
  changeType = 'neutral',
  icon: Icon,
  accentColor = 'green',
}) => {
  const colorClasses = {
    green: 'text-neon-green border-neon-green/20 bg-neon-green/5',
    red: 'text-red-400 border-red-400/20 bg-red-400/5',
    cyan: 'text-cyan-400 border-cyan-400/20 bg-cyan-400/5',
    yellow: 'text-yellow-400 border-yellow-400/20 bg-yellow-400/5',
    blue: 'text-blue-400 border-blue-400/20 bg-blue-400/5',
  };

  const changeColorClasses = {
    positive: 'text-neon-green',
    negative: 'text-red-400',
    neutral: 'text-muted-foreground',
  };

  return (
    <div className={`rounded-lg border ${colorClasses[accentColor]} bg-card p-4`}>
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon className={`h-5 w-5 ${colorClasses[accentColor].split(' ')[0]}`} />
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {title}
          </span>
        </div>
        {change && (
          <span className={`text-xs font-medium ${changeColorClasses[changeType]}`}>
            {change}
          </span>
        )}
      </div>
      <div className={`text-2xl font-bold tracking-tight ${colorClasses[accentColor].split(' ')[0]}`}>
        {value}
      </div>
    </div>
  );
};

export { KPICard };
export default KPICard;


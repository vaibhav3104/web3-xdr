import { Shield, AlertTriangle, Clock, Activity, Terminal, Radio } from "lucide-react";
import { KPICard } from "@/components/KPICard";
import { ThreatFeed } from "@/components/ThreatFeed";
import { CrossChainGraph } from "@/components/CrossChainGraph";
import { useRealtimeFeed } from "@/hooks/useRealtimeFeed";
import { useMemo } from "react";

const Index = () => {
  const { messages, isConnected } = useRealtimeFeed();

  // Calculate KPIs from real data
  const kpis = useMemo(() => {
    const threats = messages.filter(m => m.type === 'THREAT' || m.status === 'MALICIOUS');
    const totalScans = messages.length;
    const activeThreats = threats.length;
    
    // Calculate total preserved capital (would come from API)
    // For now, estimate based on threat count
    const estimatedCapital = activeThreats * 1000000; // Placeholder
    
    return {
      capitalPreserved: `$${(estimatedCapital / 1000000).toFixed(1)}M`,
      activeThreats: activeThreats.toString(),
      systemLatency: "12ms", // Would come from metrics API
    };
  }, [messages]);

  return (
    <div className="dark min-h-screen bg-background">
      {/* Top Header Bar */}
      <header className="border-b border-border bg-card/50 px-6 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <Shield className="h-6 w-6 text-primary" />
              <span className="text-lg font-bold tracking-tight text-foreground">
                WAR ROOM
              </span>
            </div>
            <div className="h-4 w-px bg-border" />
            <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Security Command Center
            </span>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Radio className={`h-4 w-4 ${isConnected ? 'animate-pulse text-neon-green' : 'text-red-500'}`} />
              <span className={`font-mono text-xs ${isConnected ? 'text-neon-green' : 'text-red-500'}`}>
                {isConnected ? 'ALL SYSTEMS OPERATIONAL' : 'CONNECTION LOST'}
              </span>
            </div>
            <div className="h-4 w-px bg-border" />
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-muted-foreground" />
              <span className="font-mono text-xs text-muted-foreground">
                {new Date().toLocaleTimeString()}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex h-[calc(100vh-57px)]">
        {/* Left Sidebar - Threat Feed */}
        <aside className="w-96 shrink-0 border-r border-border p-4">
          <ThreatFeed />
        </aside>

        {/* Center Content */}
        <main className="flex flex-1 flex-col p-4">
          {/* KPI Cards */}
          <div className="mb-4 grid grid-cols-3 gap-4">
            <KPICard
              title="Capital Preserved"
              value={kpis.capitalPreserved}
              change="+2.4%"
              changeType="positive"
              icon={Shield}
              accentColor="green"
            />
            <KPICard
              title="Active Threats"
              value={kpis.activeThreats}
              change={kpis.activeThreats !== "0" ? `-${kpis.activeThreats}` : undefined}
              changeType={kpis.activeThreats !== "0" ? "positive" : "neutral"}
              icon={AlertTriangle}
              accentColor="red"
            />
            <KPICard
              title="System Latency"
              value={kpis.systemLatency}
              change="±2ms"
              changeType="neutral"
              icon={Clock}
              accentColor="cyan"
            />
          </div>

          {/* Cross-Chain Visualization */}
          <div className="flex-1">
            <CrossChainGraph messages={messages} />
          </div>
        </main>

        {/* Right Panel - System Status */}
        <aside className="w-64 shrink-0 border-l border-border p-4">
          <div className="rounded-lg border border-border bg-card p-4">
            <div className="mb-4 flex items-center gap-2">
              <Terminal className="h-4 w-4 text-primary" />
              <span className="text-sm font-semibold text-foreground">
                System Status
              </span>
            </div>

            <div className="space-y-3">
              {[
                { name: "Threat Detection", status: isConnected ? "online" : "offline", latency: "8ms" },
                { name: "Cross-Chain Monitor", status: isConnected ? "online" : "offline", latency: "12ms" },
                { name: "Smart Contract Audit", status: isConnected ? "online" : "offline", latency: "45ms" },
                { name: "Wallet Screening", status: isConnected ? "online" : "offline", latency: "15ms" },
                { name: "Oracle Validator", status: isConnected ? "online" : "warning", latency: "89ms" },
              ].map((system) => (
                <div
                  key={system.name}
                  className="flex items-center justify-between rounded-md border border-border bg-secondary/30 px-3 py-2"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={`h-2 w-2 rounded-full ${
                        system.status === "online"
                          ? "bg-neon-green"
                          : system.status === "warning"
                          ? "bg-warning animate-pulse"
                          : "bg-red-500"
                      }`}
                    />
                    <span className="text-xs text-foreground">{system.name}</span>
                  </div>
                  <span className="font-mono text-xs text-muted-foreground">
                    {system.latency}
                  </span>
                </div>
              ))}
            </div>

            {/* Network Stats */}
            <div className="mt-6 border-t border-border pt-4">
              <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Network Coverage
              </span>
              <div className="mt-3 space-y-2">
                {[
                  { chain: "Ethereum", coverage: 98 },
                  { chain: "Solana", coverage: 95 },
                  { chain: "Polygon", coverage: 92 },
                ].map((item) => (
                  <div key={item.chain}>
                    <div className="mb-1 flex justify-between text-xs">
                      <span className="text-foreground">{item.chain}</span>
                      <span className="text-muted-foreground">{item.coverage}%</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-secondary">
                      <div
                        className="h-full rounded-full bg-primary transition-all duration-500"
                        style={{ width: `${item.coverage}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </aside>
      </div>

      {/* Scanline effect overlay */}
      <div className="scanline pointer-events-none fixed inset-0 z-50" />
    </div>
  );
};

export default Index;


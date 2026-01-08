/**
 * Demo Mode Event Generator
 * ==========================
 * 
 * Generates fake dramatic events for sales demonstrations.
 * Client-side only - bypasses backend.
 */

export interface ThreatMessage {
  type: 'SCAN' | 'THREAT' | 'GUARDIAN';
  timestamp: number;
  source_chain: string;
  tx_hash: string;
  contract: string;
  risk_score: number;
  status: 'Safe' | 'Simulating...' | 'MALICIOUS';
  details?: any;
}

export function generateDemoEvents(): ThreatMessage[] {
  const now = Math.floor(Date.now() / 1000);
  
  return [
    // T=0s: Normal traffic
    {
      type: 'SCAN',
      timestamp: now,
      source_chain: 'ethereum',
      tx_hash: '0x' + Math.random().toString(16).slice(2, 66),
      contract: '0x3ee18B2214AFF97000D974cf647E7C347E8fa585',
      risk_score: 0.1,
      status: 'Safe',
    },
    {
      type: 'SCAN',
      timestamp: now + 1,
      source_chain: 'polygon',
      tx_hash: '0x' + Math.random().toString(16).slice(2, 66),
      contract: '0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675',
      risk_score: 0.2,
      status: 'Safe',
    },
    
    // T=5s: Anomaly detected
    {
      type: 'SCAN',
      timestamp: now + 5,
      source_chain: 'solana',
      tx_hash: '0x' + Math.random().toString(16).slice(2, 66),
      contract: 'Wormhole Bridge',
      risk_score: 0.6,
      status: 'Simulating...',
      details: { anomaly: 'Unusual bridge activity detected' },
    },
    
    // T=8s: Signature mismatch
    {
      type: 'THREAT',
      timestamp: now + 8,
      source_chain: 'ethereum',
      tx_hash: '0x' + Math.random().toString(16).slice(2, 66),
      contract: '0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B',
      risk_score: 0.95,
      status: 'MALICIOUS',
      details: {
        violation: 'Signature Mismatch',
        protocol: 'Wormhole',
        severity: 'CRITICAL',
      },
    },
    
    // T=10s: Guardian triggered
    {
      type: 'GUARDIAN',
      timestamp: now + 10,
      source_chain: 'ethereum',
      tx_hash: '0x' + Math.random().toString(16).slice(2, 66),
      contract: '0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B',
      risk_score: 1.0,
      status: 'MALICIOUS',
      details: {
        action: 'PAUSED',
        protocol: 'Wormhole',
        message: 'GUARDIAN TRIGGERED - Contract paused',
      },
    },
  ];
}

export function isDemoMode(): boolean {
  if (typeof window === 'undefined') return false;
  const params = new URLSearchParams(window.location.search);
  return params.get('demo') === 'true';
}


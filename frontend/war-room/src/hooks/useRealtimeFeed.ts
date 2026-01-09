/**
 * useRealtimeFeed Hook
 * ====================
 * 
 * Connects to FastAPI WebSocket feed and maintains state of threat messages.
 * Filters for SCAN and THREAT message types.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import useWebSocket from 'react-use-websocket';

export interface ThreatMessage {
  type: 'SCAN' | 'THREAT';
  timestamp: number;
  source_chain: string;
  tx_hash: string;
  contract?: string;
  risk_score: number;
  status: 'Safe' | 'Simulating...' | 'MALICIOUS';
  details?: {
    predicted_type?: string;
    severity?: string;
    protocol?: string;
    target_chain?: string;
    cross_chain?: boolean;
    zero_day?: boolean;
  };
}

const MAX_MESSAGES = 50;
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/feed';

export function useRealtimeFeed() {
  const [messages, setMessages] = useState<ThreatMessage[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const messagesRef = useRef<ThreatMessage[]>([]);

  const { lastMessage, readyState } = useWebSocket(WS_URL, {
    onOpen: () => {
      console.log('WebSocket connected');
      setIsConnected(true);
    },
    onClose: () => {
      console.log('WebSocket disconnected');
      setIsConnected(false);
    },
    onError: (event) => {
      console.error('WebSocket error:', event);
      setIsConnected(false);
    },
    shouldReconnect: () => true,
    reconnectAttempts: 10,
    reconnectInterval: 3000,
  });

  const addMessage = useCallback((message: ThreatMessage) => {
    setMessages((prev) => {
      const updated = [message, ...prev].slice(0, MAX_MESSAGES);
      messagesRef.current = updated;
      return updated;
    });
  }, []);

  useEffect(() => {
    if (!lastMessage?.data) return;

    try {
      const data = JSON.parse(lastMessage.data);
      
      // Handle array of messages or single message
      const messagesToProcess = Array.isArray(data) ? data : [data];
      
      messagesToProcess.forEach((msg: any) => {
        // Filter for SCAN or THREAT types
        if (msg.type === 'SCAN' || msg.type === 'THREAT') {
          const threatMessage: ThreatMessage = {
            type: msg.type,
            timestamp: msg.timestamp || Date.now(),
            source_chain: msg.source_chain || msg.chain_id || 'unknown',
            tx_hash: msg.tx_hash || msg.txHash || '',
            contract: msg.contract || msg.to_address || '',
            risk_score: msg.risk_score || msg.riskScore || 0.0,
            status: msg.status || (msg.type === 'THREAT' ? 'MALICIOUS' : 'Safe'),
            details: msg.details || {
              predicted_type: msg.predicted_type,
              severity: msg.severity,
              protocol: msg.protocol || msg.protocol_id,
              target_chain: msg.target_chain,
              cross_chain: msg.cross_chain,
              zero_day: msg.zero_day,
            },
          };
          
          addMessage(threatMessage);
        }
      });
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error);
    }
  }, [lastMessage, addMessage]);

  const connectionStatus = {
    [WebSocket.CONNECTING]: 'Connecting',
    [WebSocket.OPEN]: 'Connected',
    [WebSocket.CLOSING]: 'Closing',
    [WebSocket.CLOSED]: 'Disconnected',
  }[readyState] || 'Unknown';

  return {
    messages,
    isConnected: readyState === WebSocket.OPEN,
    connectionStatus,
  };
}


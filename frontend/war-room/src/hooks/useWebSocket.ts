/**
 * WebSocket Hook
 * ==============
 * 
 * Custom hook for managing WebSocket connection to Sentinel3 feed.
 * Uses react-use-websocket for connection management.
 */

import { useWebSocket as useWS } from 'react-use-websocket';
import { useMemo, useEffect } from 'react';
import { generateDemoEvents, isDemoMode, ThreatMessage } from '../components/DemoMode';

const WS_URL = process.env.REACT_APP_WS_URL || 'ws://localhost:8080/ws/feed';

export function useWebSocket() {
  const isDemo = isDemoMode();
  
  // Real WebSocket connection (disabled in demo mode)
  const {
    lastMessage,
    sendMessage,
    readyState,
    getWebSocket,
  } = useWS(WS_URL, {
    shouldReconnect: () => !isDemo,
    reconnectAttempts: 10,
    reconnectInterval: 3000,
    onOpen: () => console.log('WebSocket connected'),
    onClose: () => console.log('WebSocket disconnected'),
    onError: (event) => console.error('WebSocket error:', event),
  });

  // Demo mode: Generate fake events
  const [demoMessages, setDemoMessages] = useState<ThreatMessage[]>([]);
  const [demoIndex, setDemoIndex] = useState(0);

  useEffect(() => {
    if (!isDemo) return;

    const demoEvents = generateDemoEvents();
    const interval = setInterval(() => {
      if (demoIndex < demoEvents.length) {
        setDemoMessages(prev => [...prev, demoEvents[demoIndex]]);
        setDemoIndex(prev => prev + 1);
      } else {
        // Loop demo events
        setDemoIndex(0);
        setDemoMessages([]);
      }
    }, 2000); // Show event every 2 seconds

    return () => clearInterval(interval);
  }, [isDemo, demoIndex]);

  // Parse messages
  const messages = useMemo(() => {
    if (isDemo) {
      return demoMessages;
    }

    if (!lastMessage?.data) return [];

    try {
      const data = JSON.parse(lastMessage.data);
      
      // Handle array of messages or single message
      if (Array.isArray(data)) {
        return data;
      }
      
      return [data];
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error);
      return [];
    }
  }, [lastMessage, isDemo, demoMessages]);

  const connectionStatus = {
    [WebSocket.CONNECTING]: 'Connecting',
    [WebSocket.OPEN]: 'Connected',
    [WebSocket.CLOSING]: 'Closing',
    [WebSocket.CLOSED]: 'Closed',
  }[readyState] || 'Unknown';

  return {
    messages,
    sendMessage,
    connectionStatus,
    isConnected: readyState === WebSocket.OPEN,
    isDemo,
  };
}


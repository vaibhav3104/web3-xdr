/**
 * Cross-Chain Graph Component
 * ============================
 * 
 * React Flow visualization showing cross-chain bridge connections.
 * - Nodes: Ethereum, Polygon, Solana, Arbitrum
 * - Edges: Bridge connections (Wormhole, LayerZero, etc.)
 * - Animated packet travel on intent scan
 * - Red pulsing edges for cross-chain attacks
 */

import React, { useCallback, useMemo } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  addEdge,
  Connection,
  MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';
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

interface CrossChainGraphProps {
  messages: ThreatMessage[];
}

const CHAIN_NODES: Node[] = [
  {
    id: 'ethereum',
    type: 'input',
    data: { label: 'Ethereum' },
    position: { x: 100, y: 200 },
    style: {
      background: '#627EEA',
      color: '#fff',
      border: '2px solid #627EEA',
      borderRadius: '8px',
      padding: '10px',
      fontWeight: 'bold',
    },
  },
  {
    id: 'polygon',
    data: { label: 'Polygon' },
    position: { x: 300, y: 100 },
    style: {
      background: '#8247E5',
      color: '#fff',
      border: '2px solid #8247E5',
      borderRadius: '8px',
      padding: '10px',
      fontWeight: 'bold',
    },
  },
  {
    id: 'arbitrum',
    data: { label: 'Arbitrum' },
    position: { x: 300, y: 300 },
    style: {
      background: '#28A0F0',
      color: '#fff',
      border: '2px solid #28A0F0',
      borderRadius: '8px',
      padding: '10px',
      fontWeight: 'bold',
    },
  },
  {
    id: 'solana',
    data: { label: 'Solana' },
    position: { x: 500, y: 200 },
    style: {
      background: '#9945FF',
      color: '#fff',
      border: '2px solid #9945FF',
      borderRadius: '8px',
      padding: '10px',
      fontWeight: 'bold',
    },
  },
];

const INITIAL_EDGES: Edge[] = [
  {
    id: 'e1-p',
    source: 'ethereum',
    target: 'polygon',
    label: 'Wormhole',
    type: 'smoothstep',
    animated: false,
    style: { stroke: '#00ff00', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#00ff00' },
  },
  {
    id: 'e1-a',
    source: 'ethereum',
    target: 'arbitrum',
    label: 'LayerZero',
    type: 'smoothstep',
    animated: false,
    style: { stroke: '#00ff00', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#00ff00' },
  },
  {
    id: 'e1-s',
    source: 'ethereum',
    target: 'solana',
    label: 'Wormhole',
    type: 'smoothstep',
    animated: false,
    style: { stroke: '#00ff00', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#00ff00' },
  },
  {
    id: 'p-s',
    source: 'polygon',
    target: 'solana',
    label: 'Stargate',
    type: 'smoothstep',
    animated: false,
    style: { stroke: '#00ff00', strokeWidth: 2 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#00ff00' },
  },
];

const CrossChainGraph: React.FC<CrossChainGraphProps> = ({ messages }) => {
  const [nodes, setNodes, onNodesChange] = useNodesState(CHAIN_NODES);
  const [edges, setEdges, onEdgesChange] = useEdgesState(INITIAL_EDGES);

  // Update edges based on threat messages
  React.useEffect(() => {
    const threats = messages.filter(m => m.type === 'THREAT' || m.status === 'MALICIOUS');
    
    setEdges(prevEdges => {
      return prevEdges.map(edge => {
        // Check if this edge is involved in a cross-chain attack
        const isThreat = threats.some(threat => {
          const sourceChain = threat.source_chain.toLowerCase();
          const targetChain = threat.details?.target_chain?.toLowerCase();
          
          return (
            (edge.source === sourceChain || edge.target === sourceChain) ||
            (targetChain && (edge.source === targetChain || edge.target === targetChain))
          );
        });

        if (isThreat) {
          return {
            ...edge,
            animated: true,
            style: {
              ...edge.style,
              stroke: '#ff0000',
              strokeWidth: 3,
            },
            markerEnd: {
              ...edge.markerEnd,
              color: '#ff0000',
            },
          };
        }

        return {
          ...edge,
          animated: false,
          style: {
            ...edge.style,
            stroke: '#00ff00',
            strokeWidth: 2,
          },
          markerEnd: {
            ...edge.markerEnd,
            color: '#00ff00',
          },
        };
      });
    });
  }, [messages, setEdges]);

  // Highlight nodes based on recent activity
  React.useEffect(() => {
    const recentMessages = messages.slice(-10);
    const activeChains = new Set(recentMessages.map(m => m.source_chain.toLowerCase()));

    setNodes(prevNodes => {
      return prevNodes.map(node => {
        const isActive = activeChains.has(node.id);
        return {
          ...node,
          style: {
            ...node.style,
            boxShadow: isActive ? '0 0 20px rgba(0, 255, 0, 0.8)' : 'none',
          },
        };
      });
    });
  }, [messages, setNodes]);

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  return (
    <div className="h-full w-full bg-black border border-green-500 rounded-lg overflow-hidden">
      <div className="px-4 py-2 bg-green-900/30 border-b border-green-500">
        <h2 className="text-green-400 font-mono text-sm font-bold">CROSS-CHAIN GRAPH</h2>
      </div>
      <div className="h-[calc(100%-40px)]">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          fitView
          className="bg-black"
        >
          <Background color="#00ff00" gap={16} opacity={0.1} />
          <Controls className="bg-black border border-green-500" />
          <MiniMap
            className="bg-black border border-green-500"
            nodeColor={(node) => {
              if (node.id === 'ethereum') return '#627EEA';
              if (node.id === 'polygon') return '#8247E5';
              if (node.id === 'arbitrum') return '#28A0F0';
              if (node.id === 'solana') return '#9945FF';
              return '#00ff00';
            }}
            maskColor="rgba(0, 0, 0, 0.8)"
          />
        </ReactFlow>
      </div>
    </div>
  );
};

export default CrossChainGraph;


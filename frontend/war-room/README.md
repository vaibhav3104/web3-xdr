# Sentinel3 War Room Dashboard

Real-time visualization dashboard for Sentinel3 threat detection.

## Features

- **Live Threat Feed**: Matrix-style terminal showing real-time transaction scans
- **Cross-Chain Graph**: React Flow visualization of bridge connections
- **Metric Cards**: Key statistics with Tremor components
- **Demo Mode**: Sales demonstration mode with fake events

## Setup

```bash
cd frontend/war-room
npm install
npm run dev
```

## Configuration

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Set WebSocket URL:
```env
REACT_APP_WS_URL=ws://localhost:8080/ws/feed
```

## Demo Mode

Add `?demo=true` to URL to enable demo mode with fake dramatic events.

## Development

```bash
# Start dev server
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview
```

## Components

- `LiveThreatFeed` - Matrix-style terminal feed
- `CrossChainGraph` - React Flow visualization
- `MetricCards` - Tremor metric cards
- `DemoMode` - Demo mode toggle and generator
- `WarRoomDashboard` - Main container

## Tech Stack

- React 18
- TypeScript
- Vite
- Tailwind CSS
- Tremor (UI components)
- React Flow (Graph visualization)
- Framer Motion (Animations)
- react-use-websocket (WebSocket hook)

## Performance

- Limited to 50 items in feed (configurable)
- Virtual scrolling for large lists
- Memoized calculations
- Optimized re-renders with React.memo

## Deployment

Build the app and serve static files:

```bash
npm run build
# Serve dist/ directory from FastAPI or any static file server
```

Or deploy to Vercel/Netlify:

```bash
npm run build
# Deploy dist/ directory
```

# War Room Dashboard - Quick Setup Guide

## Prerequisites

- Node.js 18+ and npm
- Redis running (for backend)
- Sentinel3 backend running

## Installation

```bash
cd frontend/war-room
npm install
```

## Configuration

1. Copy environment file:
```bash
cp .env.example .env
```

2. Edit `.env` and set WebSocket URL:
```env
REACT_APP_WS_URL=ws://localhost:8080/ws/feed
```

## Development

```bash
npm run dev
```

Opens at `http://localhost:3000`

## Demo Mode

Add `?demo=true` to URL:
```
http://localhost:3000?demo=true
```

## Production Build

```bash
npm run build
```

Outputs to `dist/` directory. Serve with any static file server or deploy to Vercel/Netlify.

## Troubleshooting

### WebSocket Connection Failed

1. Check backend is running on port 8080
2. Verify Redis is running
3. Check `REACT_APP_WS_URL` in `.env`

### Demo Mode Not Working

1. Ensure URL has `?demo=true`
2. Check browser console for errors
3. Verify demo events are generating

### Build Errors

1. Clear node_modules and reinstall:
```bash
rm -rf node_modules package-lock.json
npm install
```

2. Check Node.js version (requires 18+)

## Features

- ✅ Live threat feed
- ✅ Cross-chain graph
- ✅ Real-time metrics
- ✅ Demo mode
- ✅ Dark theme
- ✅ Smooth animations


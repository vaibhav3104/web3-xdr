// Sentinel3 Frontend Configuration
// This file configures the API endpoint for all frontend pages

(function() {
    // GPU-enabled API backend on Google Cloud
    const GPU_API = 'https://sentinel3-1003459948096.us-central1.run.app';
    
    // Production API (fallback)
    const PRODUCTION_API = 'https://web3-xdr-production-api-1003459948096.us-central1.run.app';
    
    // Local development
    const LOCAL_API = '';  // Empty string means same origin (relative URLs)
    
    // ============================================
    // SET THE ACTIVE API HERE
    // ============================================
    // Options: GPU_API, PRODUCTION_API, LOCAL_API
    // Always use same-origin (relative URLs) since frontend and API are co-located.
    // Only override to PRODUCTION_API or GPU_API if frontend is hosted separately.
    window.SENTINEL3_API_BASE = LOCAL_API;
    
    // Helper function for API calls
    window.sentinel3Fetch = async function(endpoint, options = {}) {
        const url = window.SENTINEL3_API_BASE + endpoint;
        return fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
    };
    
    console.log('Sentinel3 API configured:', window.SENTINEL3_API_BASE);

    // ============================================
    // WebSocket Real-Time Connection Manager
    // ============================================
    window.sentinel3WS = {
        ws: null,
        handlers: {},
        _reconnectTimer: null,
        _pingInterval: null,
        connected: false,
        _onConnectCallbacks: [],

        connect() {
            // Determine the WS URL from the API base
            const base = window.SENTINEL3_API_BASE || '';
            let wsUrl;
            if (base) {
                // Explicit API base: derive host from it
                const parsed = new URL(base, window.location.origin);
                const protocol = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
                wsUrl = protocol + '//' + parsed.host + '/ws';
            } else {
                // Same-origin
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                wsUrl = protocol + '//' + window.location.host + '/ws';
            }

            try {
                this.ws = new WebSocket(wsUrl);
            } catch (e) {
                console.warn('WebSocket connection failed:', e);
                this._scheduleReconnect();
                return;
            }

            this.ws.onopen = () => {
                this.connected = true;
                console.log('WebSocket connected');
                // Notify listeners
                this._onConnectCallbacks.forEach(fn => { try { fn(true); } catch(e) {} });
            };

            this.ws.onmessage = (event) => {
                try {
                    const msg = JSON.parse(event.data);
                    const type = msg.type || 'unknown';
                    // Dispatch to type-specific handlers
                    (this.handlers[type] || []).forEach(fn => fn(msg.data, msg));
                    // Dispatch to 'all' handlers
                    (this.handlers['all'] || []).forEach(fn => fn(msg));
                } catch(e) {
                    // Ignore parse errors
                }
            };

            this.ws.onclose = () => {
                this.connected = false;
                this._onConnectCallbacks.forEach(fn => { try { fn(false); } catch(e) {} });
                this._scheduleReconnect();
            };

            this.ws.onerror = () => {
                // onclose will fire after onerror
            };

            // Keepalive ping every 30 seconds
            if (this._pingInterval) clearInterval(this._pingInterval);
            this._pingInterval = setInterval(() => {
                if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                    this.ws.send(JSON.stringify({ action: 'ping' }));
                }
            }, 30000);
        },

        _scheduleReconnect() {
            if (this._reconnectTimer) clearTimeout(this._reconnectTimer);
            this._reconnectTimer = setTimeout(() => this.connect(), 3000);
        },

        /**
         * Subscribe to a specific message type.
         * Types: 'incident', 'event', 'alert', 'stats', 'guardian', 'connected', 'all'
         */
        on(type, handler) {
            if (!this.handlers[type]) this.handlers[type] = [];
            this.handlers[type].push(handler);
            // Also ask the server to subscribe to the channel
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(JSON.stringify({ action: 'subscribe', channel: type }));
            }
        },

        /**
         * Register a callback for connection state changes.
         * Callback receives: (connected: boolean)
         */
        onConnect(fn) {
            this._onConnectCallbacks.push(fn);
            // Immediately fire with current state
            try { fn(this.connected); } catch(e) {}
        },

        /**
         * Send a message to the server.
         */
        send(data) {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
                this.ws.send(typeof data === 'string' ? data : JSON.stringify(data));
            }
        }
    };

    // Auto-connect when config.js loads
    sentinel3WS.connect();
})();

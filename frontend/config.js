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
    
    console.log('🚀 Sentinel3 API configured:', window.SENTINEL3_API_BASE);
})();

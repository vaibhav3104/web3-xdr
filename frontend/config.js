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
    // Using PRODUCTION_API as it has PROC_TYPE=api for faster startup
    window.SENTINEL3_API_BASE = PRODUCTION_API;
    
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

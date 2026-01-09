/**
 * War Room Embed - Lazy Loading & Controls
 * Handles iframe lazy loading, IntersectionObserver, fullscreen, and error handling
 */

(function() {
    'use strict';

    // Constants
    const WAR_ROOM_URL = "https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/";
    const IFRAME_HEIGHT_DEFAULT = 780;
    const LOAD_TIMEOUT = 10000; // 10 seconds
    const INTERSECTION_THRESHOLD = 300; // pixels from viewport

    // State
    let iframeLoaded = false;
    let loadTimeoutId = null;
    let observer = null;
    let isFullscreen = false;

    // DOM Elements (will be set on init)
    let warRoomSection;
    let placeholder;
    let frameContainer;
    let loadBtn;
    let hideBtn;
    let reloadBtn;
    let fullscreenBtn;
    let autoloadCheckbox;
    let loadingOverlay;
    let errorDiv;

    /**
     * Initialize War Room embed
     */
    function init() {
        // Get DOM elements
        warRoomSection = document.getElementById('war-room');
        placeholder = document.getElementById('war-room-placeholder');
        frameContainer = document.getElementById('war-room-frame-container');
        loadBtn = document.getElementById('war-room-load-btn');
        hideBtn = document.getElementById('war-room-hide-btn');
        reloadBtn = document.getElementById('war-room-reload-btn');
        fullscreenBtn = document.getElementById('war-room-fullscreen-btn');
        autoloadCheckbox = document.getElementById('war-room-autoload-checkbox');

        if (!warRoomSection || !placeholder || !frameContainer) {
            console.warn('War Room elements not found');
            return;
        }

        // Create loading overlay if it doesn't exist
        if (!frameContainer.querySelector('.war-room-loading')) {
            loadingOverlay = document.createElement('div');
            loadingOverlay.className = 'war-room-loading';
            loadingOverlay.innerHTML = `
                <div class="war-room-spinner"></div>
                <p>Loading War Room...</p>
            `;
            frameContainer.appendChild(loadingOverlay);
        } else {
            loadingOverlay = frameContainer.querySelector('.war-room-loading');
        }

        // Create error div if it doesn't exist
        if (!warRoomSection.querySelector('.war-room-error')) {
            errorDiv = document.createElement('div');
            errorDiv.className = 'war-room-error';
            errorDiv.innerHTML = `
                <div class="error-icon">⚠️</div>
                <p>War Room failed to load. This may be due to security restrictions.</p>
                <div class="war-room-controls" style="justify-content: center; margin-top: 1rem;">
                    <button class="war-room-btn primary" onclick="window.warRoomEmbed.retryLoad()">Retry</button>
                    <a href="${WAR_ROOM_URL}" target="_blank" class="war-room-link">Open in New Tab ↗</a>
                </div>
            `;
            warRoomSection.appendChild(errorDiv);
        } else {
            errorDiv = warRoomSection.querySelector('.war-room-error');
        }

        // Event listeners
        if (loadBtn) {
            loadBtn.addEventListener('click', handleLoad);
        }
        if (hideBtn) {
            hideBtn.addEventListener('click', handleHide);
        }
        if (reloadBtn) {
            reloadBtn.addEventListener('click', handleReload);
        }
        if (fullscreenBtn) {
            fullscreenBtn.addEventListener('click', handleFullscreen);
        }
        if (autoloadCheckbox) {
            autoloadCheckbox.addEventListener('change', handleAutoloadChange);
        }

        // Setup IntersectionObserver if supported
        if ('IntersectionObserver' in window && autoloadCheckbox) {
            setupIntersectionObserver();
        }

        // Handle ESC key for fullscreen exit
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && isFullscreen) {
                exitFullscreen();
            }
        });

        // Handle fullscreen change events
        document.addEventListener('fullscreenchange', handleFullscreenChange);
        document.addEventListener('webkitfullscreenchange', handleFullscreenChange);
        document.addEventListener('mozfullscreenchange', handleFullscreenChange);
        document.addEventListener('MSFullscreenChange', handleFullscreenChange);
    }

    /**
     * Setup IntersectionObserver for auto-loading
     */
    function setupIntersectionObserver() {
        observer = new IntersectionObserver(function(entries) {
            entries.forEach(function(entry) {
                if (entry.isIntersecting && !iframeLoaded && autoloadCheckbox.checked) {
                    handleLoad();
                    observer.disconnect(); // Only load once
                }
            });
        }, {
            rootMargin: INTERSECTION_THRESHOLD + 'px'
        });

        observer.observe(placeholder);
    }

    /**
     * Handle load button click
     */
    function handleLoad() {
        if (iframeLoaded) {
            return; // Already loaded
        }

        // Show frame container
        frameContainer.style.display = 'block';
        frameContainer.classList.add('loaded');
        placeholder.style.display = 'none';
        errorDiv.classList.remove('show');

        // Create iframe if it doesn't exist
        let iframe = frameContainer.querySelector('iframe');
        if (!iframe) {
            iframe = document.createElement('iframe');
            iframe.id = 'war-room-iframe';
            iframe.src = WAR_ROOM_URL;
            iframe.width = '100%';
            iframe.height = IFRAME_HEIGHT_DEFAULT + 'px';
            iframe.frameBorder = '0';
            iframe.loading = 'lazy';
            iframe.style.borderRadius = '8px';
            iframe.style.display = 'block';
            frameContainer.appendChild(iframe);
        }

        // Show loading overlay
        loadingOverlay.classList.remove('hidden');

        // Set timeout
        loadTimeoutId = setTimeout(function() {
            if (!iframeLoaded) {
                handleLoadError();
            }
        }, LOAD_TIMEOUT);

        // Handle iframe load
        iframe.addEventListener('load', function() {
            iframeLoaded = true;
            loadingOverlay.classList.add('hidden');
            if (loadTimeoutId) {
                clearTimeout(loadTimeoutId);
            }
            updateButtonStates();
        }, { once: true });

        // Handle iframe error
        iframe.addEventListener('error', function() {
            handleLoadError();
        }, { once: true });

        // Update button states
        updateButtonStates();
    }

    /**
     * Handle load error
     */
    function handleLoadError() {
        iframeLoaded = false;
        loadingOverlay.classList.add('hidden');
        errorDiv.classList.add('show');
        frameContainer.style.display = 'none';
        placeholder.style.display = 'block';

        // Check for X-Frame-Options blocking
        const iframe = frameContainer.querySelector('iframe');
        if (iframe) {
            try {
                // Try to access iframe content (will fail if blocked)
                iframe.contentWindow;
            } catch (e) {
                errorDiv.querySelector('p').textContent = 
                    'Embedding blocked by War Room headers. Use Full Page / New Tab.';
            }
        }

        if (loadTimeoutId) {
            clearTimeout(loadTimeoutId);
        }
        updateButtonStates();
    }

    /**
     * Handle hide button click
     */
    function handleHide() {
        warRoomSection.classList.add('collapsed');
        frameContainer.style.display = 'none';
        placeholder.style.display = 'block';
        updateButtonStates();
    }

    /**
     * Handle reload button click
     */
    function handleReload() {
        const iframe = frameContainer.querySelector('iframe');
        if (iframe) {
            iframeLoaded = false;
            iframe.src = ''; // Clear src
            setTimeout(function() {
                iframe.src = WAR_ROOM_URL; // Reload
                loadingOverlay.classList.remove('hidden');
                handleLoad();
            }, 100);
        }
    }

    /**
     * Handle fullscreen button click
     */
    function handleFullscreen() {
        if (isFullscreen) {
            exitFullscreen();
        } else {
            enterFullscreen();
        }
    }

    /**
     * Enter fullscreen
     */
    function enterFullscreen() {
        if (!frameContainer.classList.contains('loaded')) {
            handleLoad(); // Load if not loaded
            setTimeout(enterFullscreen, 500);
            return;
        }

        if (frameContainer.requestFullscreen) {
            frameContainer.requestFullscreen();
        } else if (frameContainer.webkitRequestFullscreen) {
            frameContainer.webkitRequestFullscreen();
        } else if (frameContainer.mozRequestFullScreen) {
            frameContainer.mozRequestFullScreen();
        } else if (frameContainer.msRequestFullscreen) {
            frameContainer.msRequestFullscreen();
        } else {
            // Fallback to overlay
            frameContainer.classList.add('war-room-overlay');
            document.body.style.overflow = 'hidden';
            isFullscreen = true;
            updateButtonStates();
        }
    }

    /**
     * Exit fullscreen
     */
    function exitFullscreen() {
        if (document.exitFullscreen) {
            document.exitFullscreen();
        } else if (document.webkitExitFullscreen) {
            document.webkitExitFullscreen();
        } else if (document.mozCancelFullScreen) {
            document.mozCancelFullScreen();
        } else if (document.msExitFullscreen) {
            document.msExitFullscreen();
        } else {
            // Fallback overlay
            frameContainer.classList.remove('war-room-overlay');
            document.body.style.overflow = '';
            isFullscreen = false;
            updateButtonStates();
        }
    }

    /**
     * Handle fullscreen change events
     */
    function handleFullscreenChange() {
        const isCurrentlyFullscreen = !!(
            document.fullscreenElement ||
            document.webkitFullscreenElement ||
            document.mozFullScreenElement ||
            document.msFullscreenElement
        );

        isFullscreen = isCurrentlyFullscreen;
        updateButtonStates();
    }

    /**
     * Handle autoload checkbox change
     */
    function handleAutoloadChange() {
        if (autoloadCheckbox.checked && !iframeLoaded && observer) {
            // Re-observe if unchecked then checked
            observer.observe(placeholder);
        }
    }

    /**
     * Update button states
     */
    function updateButtonStates() {
        if (loadBtn) {
            loadBtn.style.display = iframeLoaded ? 'none' : 'inline-block';
        }
        if (hideBtn) {
            hideBtn.style.display = iframeLoaded ? 'inline-block' : 'none';
        }
        if (reloadBtn) {
            reloadBtn.style.display = iframeLoaded ? 'inline-block' : 'none';
        }
        if (fullscreenBtn) {
            fullscreenBtn.textContent = isFullscreen ? 'Exit Fullscreen' : 'Fullscreen';
            fullscreenBtn.style.display = iframeLoaded ? 'inline-block' : 'none';
        }
    }

    /**
     * Retry loading (public API)
     */
    function retryLoad() {
        const iframe = frameContainer.querySelector('iframe');
        if (iframe) {
            iframe.remove();
        }
        iframeLoaded = false;
        errorDiv.classList.remove('show');
        handleLoad();
    }

    /**
     * Smooth scroll to War Room section
     */
    function scrollToWarRoom() {
        if (warRoomSection) {
            warRoomSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
            // Expand if collapsed
            if (warRoomSection.classList.contains('collapsed')) {
                warRoomSection.classList.remove('collapsed');
            }
            // Highlight nav link
            const navLink = document.getElementById('nav-war-room');
            if (navLink) {
                navLink.classList.add('active');
                setTimeout(function() {
                    navLink.classList.remove('active');
                }, 2000);
            }
        }
    }

    // Public API
    window.warRoomEmbed = {
        load: handleLoad,
        hide: handleHide,
        reload: handleReload,
        fullscreen: handleFullscreen,
        retryLoad: retryLoad,
        scrollTo: scrollToWarRoom
    };

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();

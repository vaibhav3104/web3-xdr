/**
 * Sentinel3 — Premium Navigation & Design System v2.0
 * ====================================================
 * Injects shared theme variables, ambient background effects,
 * and a glassmorphism sidebar into every page.
 */
(function () {
    // ── Navigation Items ────────────────────────────────────────────
    const NAV_ITEMS = [
        { section: 'Monitor' },
        { href: '/',                        label: 'Dashboard',      icon: 'grid' },
        { href: '/frontend/incidents.html', label: 'Incidents',      icon: 'alert' },
        { href: '/frontend/timeline.html',  label: 'Timeline',       icon: 'play' },
        { href: '/frontend/logs.html',      label: 'Log Explorer',   icon: 'file' },
        { href: '/frontend/analytics.html', label: 'Analytics',      icon: 'chart' },
        { section: 'Defend' },
        { href: '/frontend/guardian.html',       label: 'Guardian',       icon: 'shield' },
        { href: '/frontend/scanner.html',        label: 'Scanner',        icon: 'search' },
        { href: '/frontend/security-graph.html', label: 'Security Graph', icon: 'link' },
        { href: '/frontend/fund-tracing.html',   label: 'Fund Tracing',   icon: 'git' },
        { href: '/frontend/simulator.html',      label: 'Simulator',      icon: 'play' },
        { href: '/frontend/ml-analysis.html',    label: 'ML Analysis',    icon: 'cpu' },
        { href: '/frontend/risk-checker.html',   label: 'Risk Checker',   icon: 'check' },
        { href: '/frontend/threat-intel.html',   label: 'Threat Intel',   icon: 'alert' },
        { section: 'Configure' },
        { href: '/frontend/invariant-builder.html', label: 'Invariant Builder', icon: 'shield' },
        { href: '/frontend/parsers.html',    label: 'Parsers',    icon: 'settings' },
        { href: '/frontend/protocols.html',  label: 'Protocols',  icon: 'layers' },
        { href: '/frontend/cross-chain.html',label: 'Cross-Chain', icon: 'git' },
        { href: '/frontend/tenants.html',    label: 'Tenants',    icon: 'users' },
        { href: '/frontend/admin.html',      label: 'Admin',      icon: 'sliders' },
    ];

    // ── SVG Icon Paths ──────────────────────────────────────────────
    const ICONS = {
        grid:    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z"/>',
        alert:   '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/>',
        file:    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>',
        chart:   '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>',
        shield:  '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>',
        search:  '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>',
        link:    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>',
        play:    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>',
        cpu:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/>',
        check:   '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>',
        settings:'<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>',
        layers:  '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/>',
        git:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"/>',
        users:   '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>',
        sliders: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/>',
        logout:  '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>',
        collapse:'<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M11 19l-7-7 7-7m8 14l-7-7 7-7"/>',
        expand:  '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 5l7 7-7 7M5 5l7 7-7 7"/>',
    };

    function svgIcon(name, size) {
        const s = size || '1.125rem';
        return '<svg style="width:' + s + ';height:' + s + ';flex-shrink:0;" fill="none" stroke="currentColor" viewBox="0 0 24 24">' + (ICONS[name] || '') + '</svg>';
    }

    function isActive(href) {
        const path = window.location.pathname;
        if (href === '/') return path === '/' || path === '/index.html';
        return path === href || path === href.replace('/frontend/', '/');
    }

    // ── Shared Design System Styles ─────────────────────────────────
    function injectTheme() {
        // Theme CSS is now loaded statically via theme.css in <head>.
        // This function is kept as a fallback for pages that don't include theme.css.
        if (document.getElementById('s3-theme')) return;
        // Check if theme.css is already loaded (CSS variable will be defined)
        if (getComputedStyle(document.documentElement).getPropertyValue('--s3-bg-0').trim()) return;
        const link = document.createElement('link');
        link.id = 's3-theme';
        link.rel = 'stylesheet';
        link.href = '/frontend/theme.css';
        document.head.prepend(link);
    }

    // Reveal body after sidebar is injected (theme.css hides body via opacity:0)
    function revealPage() {
        document.body.classList.add('s3-ready');
    }

    // ── Build Sidebar HTML ──────────────────────────────────────────
    function buildSidebar() {
        let user = 'admin', role = 'operator';
        try {
            const u = JSON.parse(localStorage.getItem('xdr_user'));
            user = u?.username || 'admin';
            role = u?.role || 'operator';
        } catch {}

        const collapsed = localStorage.getItem('s3_nav_collapsed') === '1';
        const miniClass = collapsed ? ' mini' : '';

        let html = '<aside id="s3-sidebar" class="' + miniClass + '">';

        // Logo
        html += '<a href="/" class="s3-logo-area" style="text-decoration:none;">';
        html += '<div class="s3-logo-mark"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg></div>';
        html += '<div class="s3-logo-text"><div class="s3-logo-name">Sentinel3</div><div class="s3-logo-sub">Web3 XDR</div></div>';
        html += '</a>';

        // Nav
        html += '<nav class="s3-nav">';
        for (const item of NAV_ITEMS) {
            if (item.section) {
                html += '<div class="s3-section-label">' + item.section + '</div>';
                continue;
            }
            const active = isActive(item.href);
            html += '<a href="' + item.href + '" class="s3-nav-item' + (active ? ' active' : '') + '" data-label="' + item.label + '">';
            html += svgIcon(item.icon);
            html += '<span>' + item.label + '</span>';
            html += '</a>';
        }
        html += '</nav>';

        // Footer
        html += '<div class="s3-nav-footer">';

        // User
        html += '<div class="s3-nav-user">';
        html += '<div class="s3-avatar">' + user.charAt(0).toUpperCase() + '</div>';
        html += '<div class="s3-user-info"><div class="s3-user-name">' + user + '</div><div class="s3-user-role">' + role + '</div></div>';
        html += '<button class="s3-logout-btn" onclick="localStorage.removeItem(\'xdr_token\');localStorage.removeItem(\'xdr_user\');window.location.href=\'/frontend/login.html\'" title="Sign out">' + svgIcon('logout', '1rem') + '</button>';
        html += '</div>';

        // Collapse button
        html += '<button class="s3-collapse-btn" id="s3-toggle-btn">';
        html += '<span id="s3-toggle-icon">' + svgIcon(collapsed ? 'expand' : 'collapse', '0.875rem') + '</span>';
        html += '<span>Collapse</span>';
        html += '</button>';

        html += '</div></aside>';
        return html;
    }

    // ── Inject Ambient Background ───────────────────────────────────
    function injectAmbient() {
        if (document.getElementById('s3-ambient')) return;
        const el = document.createElement('div');
        el.id = 's3-ambient';
        document.body.prepend(el);
    }

    // ── Toggle Sidebar ──────────────────────────────────────────────
    function setupToggle() {
        const btn = document.getElementById('s3-toggle-btn');
        const sidebar = document.getElementById('s3-sidebar');
        if (!btn || !sidebar) return;

        btn.addEventListener('click', function () {
            const isCollapsed = sidebar.classList.toggle('mini');
            localStorage.setItem('s3_nav_collapsed', isCollapsed ? '1' : '0');
            document.getElementById('s3-toggle-icon').innerHTML = svgIcon(isCollapsed ? 'expand' : 'collapse', '0.875rem');
        });
    }

    // ── Main Inject ─────────────────────────────────────────────────
    function inject() {
        if (window.location.pathname.includes('login')) {
            revealPage();
            return;
        }
        if (document.getElementById('s3-sidebar')) {
            revealPage();
            return;
        }

        injectTheme();
        injectAmbient();

        document.body.style.cssText += ';display:flex;min-height:100vh;margin:0;';

        const temp = document.createElement('div');
        temp.innerHTML = buildSidebar();
        const aside = temp.firstElementChild;
        document.body.prepend(aside);

        const app = document.getElementById('app') || document.body.querySelector('[x-data]');
        if (app && app !== document.body) {
            app.style.flex = '1';
            app.style.minWidth = '0';
            app.style.position = 'relative';
            app.style.zIndex = '1';
        }

        setupToggle();
        revealPage();
    }

    // Fallback: reveal page even if inject() hasn't run (e.g. script error)
    setTimeout(revealPage, 800);

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', inject);
    } else {
        inject();
    }
})();

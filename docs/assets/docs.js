// AgentCop Documentation — Interactive Layer

(function() {
  'use strict';

  // ── Sidebar toggle (mobile) ────────────────────────────
  const sidebar = document.querySelector('.doc-sidebar');
  const overlay = document.querySelector('.sidebar-overlay');
  const menuBtn = document.querySelector('.menu-toggle');

  if (menuBtn && sidebar) {
    menuBtn.addEventListener('click', () => {
      sidebar.classList.toggle('open');
      if (overlay) overlay.classList.toggle('visible');
    });
  }

  if (overlay) {
    overlay.addEventListener('click', () => {
      sidebar?.classList.remove('open');
      overlay.classList.remove('visible');
    });
  }

  // ── Mark active nav item ──────────────────────────────
  const currentPath = window.location.pathname.replace(/\/$/, '');
  document.querySelectorAll('.nav-item').forEach(link => {
    const href = link.getAttribute('href')?.replace(/\/$/, '');
    if (href && (currentPath === href || currentPath.endsWith(href))) {
      link.classList.add('active');
    }
  });

  // ── Copy buttons on code blocks ───────────────────────
  document.querySelectorAll('.code-block').forEach(block => {
    const btn = block.querySelector('.copy-btn');
    const code = block.querySelector('pre code');
    if (!btn || !code) return;

    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(code.innerText.trim());
        btn.classList.add('copied');
        btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Copied`;
        setTimeout(() => {
          btn.classList.remove('copied');
          btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy`;
        }, 2000);
      } catch {
        btn.textContent = 'Failed';
      }
    });

    // Initial icon
    btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg> Copy`;
  });

  // ── Right nav scroll spy ──────────────────────────────
  const rightNavLinks = document.querySelectorAll('.right-nav-list a');
  if (rightNavLinks.length) {
    const headings = [];
    rightNavLinks.forEach(link => {
      const id = link.getAttribute('href')?.slice(1);
      if (id) {
        const el = document.getElementById(id);
        if (el) headings.push({ el, link });
      }
    });

    const observer = new IntersectionObserver(entries => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          rightNavLinks.forEach(l => l.classList.remove('active'));
          const match = headings.find(h => h.el === entry.target);
          if (match) match.link.classList.add('active');
        }
      });
    }, { rootMargin: '-20% 0% -70% 0%' });

    headings.forEach(({ el }) => observer.observe(el));
  }

  // ── Keyboard shortcut: / to focus search ─────────────
  document.addEventListener('keydown', e => {
    if (e.key === '/' && e.target.tagName !== 'INPUT') {
      e.preventDefault();
      document.querySelector('.search-input')?.focus();
    }
  });

  // ── Simple search filter (sidebar nav) ────────────────
  const searchInput = document.querySelector('.search-input');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      const q = searchInput.value.toLowerCase().trim();
      if (!q) {
        document.querySelectorAll('.nav-item').forEach(el => el.style.display = '');
        document.querySelectorAll('.nav-section-label').forEach(el => el.style.display = '');
        return;
      }
      document.querySelectorAll('.nav-item').forEach(el => {
        const match = el.textContent.toLowerCase().includes(q);
        el.style.display = match ? '' : 'none';
      });
      document.querySelectorAll('.nav-section-label').forEach(label => {
        const section = label.closest('.nav-section');
        if (!section) return;
        const visible = [...section.querySelectorAll('.nav-item')].some(el => el.style.display !== 'none');
        label.style.display = visible ? '' : 'none';
      });
    });
  }

})();

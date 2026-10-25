(function () {
  'use strict';
  if (!globalThis.FSF || !/^https?:$/.test(location.protocol)) return;

  const processed = new WeakMap();
  const originallyHidden = new WeakMap();
  let settings = FSF.normalizeSettings();
  let regex = FSF.buildKeywordRegex(FSF.DEFAULT_KEYWORDS.standard);
  let observer = null;
  let pending = new Set();
  let timer = 0;
  const attrs = ['alt', 'aria-label', 'data-src', 'data-srcset', 'poster', 'src', 'srcset', 'title'];

  function pageAllowed() {
    return FSF.isWhitelisted(location.hostname, settings.whitelist);
  }
  function active() {
    return settings.blockAdult && settings.scanContent && !pageAllowed();
  }
  function values(element) {
    const tag = element.tagName.toLowerCase();
    const result = attrs.map(name => element.getAttribute(name)).filter(Boolean);
    if (tag === 'img') result.push(element.currentSrc, element.src);
    if (tag === 'video') result.push(element.currentSrc, element.src);
    return result;
  }
  function suspect(element) {
    const text = values(element).join(' ');
    return FSF.matchesKeyword(text, regex);
  }
  function hide(element) {
    if (!element.isConnected || element.dataset.blockemHidden === '1') return;
    const dimensions = element.getBoundingClientRect();
    const placeholder = document.createElement('div');
    placeholder.className = 'blockem-placeholder';
    placeholder.setAttribute('role', 'img');
    placeholder.setAttribute('aria-label', 'Media hidden by Blockem');
    placeholder.textContent = 'Media hidden by Blockem';
    placeholder.style.cssText = 'display:flex;align-items:center;justify-content:center;min-height:64px;min-width:120px;background:#eef2f7;border:1px dashed #64748b;color:#334155;font:14px system-ui,sans-serif;text-align:center;';
    if (dimensions.width > 40) placeholder.style.width = Math.min(dimensions.width, 720) + 'px';
    if (dimensions.height > 40) placeholder.style.height = Math.min(dimensions.height, 480) + 'px';
    placeholder.addEventListener('click', event => {
      event.preventDefault();
      event.stopPropagation();
    }, true);
    const target = element.tagName === 'IMG' && element.parentElement && element.parentElement.tagName === 'PICTURE'
      ? element.parentElement : element;
    target.before(placeholder);
    originallyHidden.set(target, target.hidden);
    target.hidden = true;
    target.dataset.blockemHidden = '1';
  }
  function scan(root) {
    if (!active() || !root) return;
    const candidates = [];
    if (root.nodeType === 1 && /^(IMG|VIDEO|IFRAME)$/.test(root.tagName)) candidates.push(root);
    if (root.nodeType === 1 && root.tagName === 'SOURCE' && root.parentElement && root.parentElement.tagName === 'VIDEO') candidates.push(root.parentElement);
    if (root.querySelectorAll) candidates.push(...root.querySelectorAll('img,video,iframe'));
    for (const element of candidates) {
      const fingerprint = values(element).join('\u0000');
      if (processed.get(element) === fingerprint) continue;
      processed.set(element, fingerprint);
      if (suspect(element)) hide(element);
    }
  }
  function schedule(root) {
    if (root) pending.add(root);
    if (timer) return;
    const run = () => {
      timer = 0;
      const roots = Array.from(pending);
      pending.clear();
      roots.forEach(scan);
    };
    timer = window.setTimeout(() => {
      if ('requestIdleCallback' in window) window.requestIdleCallback(run, { timeout: 500 });
      else run();
    }, 100);
  }
  function apply() {
    if (!active()) {
      if (observer) observer.disconnect();
      observer = null;
      document.querySelectorAll('.blockem-placeholder').forEach(node => node.remove());
      document.querySelectorAll('[data-blockem-hidden="1"]').forEach(node => {
        node.hidden = originallyHidden.get(node) === true;
        originallyHidden.delete(node);
        delete node.dataset.blockemHidden;
      });
      return;
    }
    if (settings.dynamicFiltering && !observer && document.documentElement) {
      observer = new MutationObserver(changes => changes.forEach(change => {
        if (change.type === 'attributes') schedule(change.target);
        else change.addedNodes.forEach(node => { if (node.nodeType === 1) schedule(node); });
      }));
      observer.observe(document.documentElement, { attributes: true, attributeFilter: attrs, childList: true, subtree: true });
    } else if (!settings.dynamicFiltering && observer) {
      observer.disconnect();
      observer = null;
    }
    schedule(document.documentElement);
  }
  async function refresh() {
    try {
      const config = await browser.runtime.sendMessage({ action: 'getConfig' });
      settings = FSF.normalizeSettings(config.settings);
      regex = FSF.buildKeywordRegex([
        ...(FSF.DEFAULT_KEYWORDS[settings.strictness] || FSF.DEFAULT_KEYWORDS.standard),
        ...(config.keywords || []), ...settings.customKeywords
      ]);
    } catch (error) {
      console.warn('[Blockem] Could not refresh page filters:', error);
    }
    apply();
  }
  function ready() {
    refresh();
    browser.runtime.onMessage.addListener(message => {
      if (message && message.action === 'refreshFilters') refresh();
    });
    browser.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes.settings) refresh();
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', ready, { once: true });
  else ready();
})();

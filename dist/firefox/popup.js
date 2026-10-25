(function () {
  'use strict';
  const state = { settings: FSF.normalizeSettings(), host: null, cookieStoreId: null, authToken: '', config: null };
  const $ = id => document.getElementById(id);
  document.addEventListener('DOMContentLoaded', init);

  async function send(action, extra) {
    return browser.runtime.sendMessage({ action, ...(extra || {}) });
  }
  async function init() {
    try {
      const [tabs, config] = await Promise.all([
        browser.tabs.query({ active: true, currentWindow: true }),
        send('getConfig')
      ]);
      state.config = config;
      state.settings = FSF.normalizeSettings(config.settings);
      try { if (tabs[0] && tabs[0].url) state.host = FSF.normalizeHost(new URL(tabs[0].url).hostname); } catch (_) {}
      state.cookieStoreId = tabs[0] && tabs[0].cookieStoreId || null;
      await render();
    } catch (error) {
      notice('Blockem could not load its settings. Reload the extension and try again.', true);
    }
    document.querySelectorAll('[data-setting]').forEach(input => input.addEventListener('change', updateSetting));
    $('whitelistButton').addEventListener('click', toggleWhitelist);
    $('openOptions').addEventListener('click', () => browser.runtime.openOptionsPage().catch(() => notice('Could not open the dashboard.', true)));
    document.querySelectorAll('[data-pause]').forEach(button => button.addEventListener('click', () => pause(button.dataset.pause)));
    $('resumeButton').addEventListener('click', resume);
  }
  async function render() {
    for (const control of document.querySelectorAll('[data-setting]')) control.value === 'on' || control.type === 'checkbox'
      ? (control.checked = state.settings[control.dataset.setting])
      : (control.value = state.settings[control.dataset.setting]);
    $('siteHost').textContent = state.host || 'This page cannot be managed';
    $('whitelistButton').disabled = !state.host;
    const whitelisted = state.host && FSF.isWhitelisted(state.host, state.settings.whitelist);
    $('whitelistButton').textContent = whitelisted ? 'Remove from whitelist' : 'Add to whitelist';
    const status = state.host ? await send('checkSiteStatus', { hostname: state.host, cookieStoreId: state.cookieStoreId }) : { status: 'allowed' };
    $('siteStatus').textContent = status.status === 'blocked' ? 'Blocked (' + status.reason + ')' : status.status === 'whitelisted' ? 'Whitelisted' : 'Allowed';
    const paused = state.settings.pauseUntil === -1 || state.settings.pauseUntil > Date.now();
    $('pauseStatus').textContent = paused
      ? state.settings.pauseUntil === -1 ? 'Protection is paused until the browser restarts.' : 'Protection is paused until ' + new Date(state.settings.pauseUntil).toLocaleTimeString() + '.'
      : 'Protection is active.';
    $('resumeButton').classList.toggle('hidden', !paused);
    const active = [state.settings.blockAdult, state.settings.blockPhishing, state.settings.enforceSafeSearch].filter(Boolean).length;
    $('statusPill').textContent = paused ? 'Paused' : active ? 'Active' : 'Off';
    $('statusPill').className = 'status-pill ' + (paused || active < 3 ? 'limited' : 'active');
    $('statusText').textContent = paused ? 'Protection is paused' : active ? 'Protection is active' : 'Protection is turned off';
    const list = $('activityList');
    list.replaceChildren();
    const activity = (state.config && state.config.activity || []).slice(0, 5);
    if (!activity.length) list.appendChild(Object.assign(document.createElement('li'), { textContent: 'No recent blocks.' }));
    activity.forEach(item => {
      const row = document.createElement('li');
      row.textContent = item.hostname + ' — ' + item.reason;
      list.appendChild(row);
    });
  }
  async function updateSetting(event) {
    const input = event.currentTarget;
    const key = input.dataset.setting;
    const oldValue = state.settings[key];
    const value = input.type === 'checkbox' ? input.checked : input.value;
    try {
      const result = await send('updateSettings', { settings: { [key]: value }, authToken: state.authToken });
      if (!result.ok) throw new Error(result.error);
      state.settings = FSF.normalizeSettings(result.settings);
      await render();
      notice('Setting saved.');
    } catch (error) {
      if (input.type === 'checkbox') input.checked = oldValue; else input.value = oldValue;
      notice(error.message || 'Could not save setting.', true);
    }
  }
  async function toggleWhitelist() {
    const add = !FSF.isWhitelisted(state.host, state.settings.whitelist);
    try {
      const result = await send(add ? 'addWhitelist' : 'removeWhitelist', { domain: state.host, authToken: state.authToken });
      if (!result.ok) throw new Error(result.error);
      state.settings = FSF.normalizeSettings(result.settings);
      await render();
      notice(add ? 'Site added to the whitelist.' : 'Site removed from the whitelist.');
    } catch (error) { notice(error.message || 'Could not update whitelist.', true); }
  }
  async function pause(duration) {
    const result = await send('pause', { duration: duration === 'restart' ? 'restart' : Number(duration) });
    if (!result.ok) return notice(result.error, true);
    state.settings = FSF.normalizeSettings(result.settings);
    await render();
  }
  async function resume() {
    const result = await send('resume');
    if (!result.ok) return notice(result.error, true);
    state.settings = FSF.normalizeSettings(result.settings);
    await render();
  }
  function notice(text, error) {
    const element = $('notice');
    element.textContent = text;
    element.className = 'notice' + (error ? ' error' : '');
  }
})();

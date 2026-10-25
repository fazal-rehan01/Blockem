(function () {
  'use strict';
  const state = { settings: FSF.normalizeSettings(), config: null, authToken: '', passwordEnabled: false };
  const $ = id => document.getElementById(id);
  document.addEventListener('DOMContentLoaded', init);

  async function send(action, data) {
    const response = await browser.runtime.sendMessage({ action, ...(data || {}) });
    if (!response || response.ok === false) throw new Error(response && response.error || 'The request failed.');
    return response;
  }
  async function init() {
    bindEvents();
    try {
      state.config = await send('getConfig');
      state.settings = FSF.normalizeSettings(state.config.settings);
      state.passwordEnabled = state.config.passwordEnabled;
      render();
    } catch (error) { toast('Could not load settings: ' + error.message, true); }
  }
  function bindEvents() {
    document.querySelectorAll('[data-setting]').forEach(input => input.addEventListener('change', saveToggle));
    $('saveAdultDomains').addEventListener('click', () => saveDomainList('adultDomains', 'adultDomains', 'adultDomainCount'));
    $('savePhishingDomains').addEventListener('click', () => saveDomainList('phishingDomains', 'phishingDomains', 'phishingDomainCount'));
    $('clearAdultDomains').addEventListener('click', () => clearList('adultDomains', 'adultDomains'));
    $('clearPhishingDomains').addEventListener('click', () => clearList('phishingDomains', 'phishingDomains'));
    $('adultFile').addEventListener('change', event => readListFile(event, 'adultDomains', 'adultDomains'));
    $('phishingFile').addEventListener('change', event => readListFile(event, 'phishingDomains', 'phishingDomains'));
    $('saveKeywords').addEventListener('click', saveKeywords);
    $('whitelistForm').addEventListener('submit', addWhitelist);
    $('reloadLists').addEventListener('click', reloadLists);
    $('clearActivity').addEventListener('click', clearActivity);
    $('updateRemote').addEventListener('click', updateRemote);
    $('profileContainer').addEventListener('change', renderProfile);
    $('saveProfile').addEventListener('click', saveProfile);
    $('unlockPassword').addEventListener('click', unlock);
    $('setPassword').addEventListener('click', setPassword);
    $('removePassword').addEventListener('click', removePassword);
    $('exportSettings').addEventListener('click', exportSettings);
    $('importSettings').addEventListener('click', () => $('importFile').click());
    $('importFile').addEventListener('change', importSettings);
    $('resetDefaults').addEventListener('click', resetDefaults);
    document.querySelectorAll('[data-pause]').forEach(button => button.addEventListener('click', () => pause(button.dataset.pause)));
    $('resumeButton').addEventListener('click', resume);
  }
  function render() {
    document.querySelectorAll('[data-setting]').forEach(input => {
      const value = state.settings[input.dataset.setting];
      if (input.type === 'checkbox') input.checked = Boolean(value);
      else input.value = value;
    });
    $('adultDomains').value = state.settings.adultDomains.join('\n');
    $('phishingDomains').value = state.settings.phishingDomains.join('\n');
    $('customKeywords').value = state.settings.customKeywords.join('\n');
    $('remoteAdultUrl').value = state.settings.remoteAdultUrl;
    $('remotePhishingUrl').value = state.settings.remotePhishingUrl;
    $('updateFrequencyHours').value = state.settings.updateFrequencyHours;
    renderCounts();
    renderDomainChips('adultDomains', 'adultDomainChips');
    renderDomainChips('phishingDomains', 'phishingDomainChips');
    renderWhitelist();
    renderLists();
    renderActivity();
    renderProfiles();
    renderPasswordState();
    renderStatus();
    const paused = state.settings.pauseUntil === -1 || state.settings.pauseUntil > Date.now();
    $('pauseStatus').textContent = paused ? state.settings.pauseUntil === -1 ? 'Paused until Firefox restarts.' : 'Paused until ' + new Date(state.settings.pauseUntil).toLocaleString() : 'Protection is active.';
    $('remoteUpdated').textContent = state.config.remoteUpdatedAt ? 'Last updated: ' + new Date(state.config.remoteUpdatedAt).toLocaleString() : 'No remote list download yet.';
  }
  function renderCounts() {
    $('adultDomainCount').textContent = state.settings.adultDomains.length + ' domains';
    $('phishingDomainCount').textContent = state.settings.phishingDomains.length + ' domains';
  }
  function renderDomainChips(key, elementId) {
    const list = $(elementId);
    list.replaceChildren();
    state.settings[key].forEach(host => {
      const item = document.createElement('li');
      item.className = 'chip';
      const label = document.createElement('span');
      label.textContent = host;
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.textContent = 'Remove';
      remove.setAttribute('aria-label', 'Remove ' + host + ' from this list');
      remove.addEventListener('click', async () => {
        const next = state.settings[key].filter(entry => entry !== host);
        try {
          await savePatch({ [key]: next });
          toast('Domain removed from list.');
        } catch (error) { toast(error.message, true); }
      });
      item.append(label, remove);
      list.appendChild(item);
    });
  }
  function renderStatus() {
    const count = [state.settings.blockAdult, state.settings.blockPhishing, state.settings.enforceSafeSearch].filter(Boolean).length;
    const pill = $('protectionPill');
    const paused = state.settings.pauseUntil === -1 || state.settings.pauseUntil > Date.now();
    pill.textContent = paused ? 'Paused' : count === 0 ? 'Off' : count === 3 ? 'Active' : 'Limited';
    pill.className = 'status-pill ' + (paused || count < 3 ? 'limited' : 'active');
  }
  function renderLists() {
    const status = state.config.listStatus || {};
    $('adultCount').textContent = String(status.adult || 0);
    $('phishingCount').textContent = String(status.phishing || 0);
    $('keywordCount').textContent = String(status.keywords || 0);
    const errors = $('listErrors');
    errors.replaceChildren();
    errors.classList.toggle('hidden', !(status.errors && status.errors.length));
    (status.errors || []).forEach(text => { const item = document.createElement('li'); item.textContent = text; errors.appendChild(item); });
  }
  function renderActivity() {
    const list = $('activityList');
    list.replaceChildren();
    const rows = state.config.activity || [];
    if (!rows.length) list.appendChild(Object.assign(document.createElement('li'), { textContent: 'No recent blocks.' }));
    rows.slice(0, 20).forEach(entry => {
      const row = document.createElement('li');
      const when = Number(entry.timestamp);
      row.textContent = entry.hostname + ' — ' + entry.reason + ' — ' + (Number.isFinite(when) ? new Date(when).toLocaleString() : 'unknown time');
      list.appendChild(row);
    });
  }
  function renderProfiles() {
    const select = $('profileContainer');
    const previous = select.value;
    select.replaceChildren(new Option('Choose a container', ''));
    (state.config.profileIdentities || []).forEach(identity => select.add(new Option(identity.name, identity.cookieStoreId)));
    if (previous && Array.from(select.options).some(option => option.value === previous)) select.value = previous;
    renderProfile();
  }
  function renderProfile() {
    const id = $('profileContainer').value;
    const profile = state.settings.containerProfiles[id] || {};
    $('profileBlockAdult').checked = profile.blockAdult !== false;
    $('profileSafeSearch').checked = profile.enforceSafeSearch !== false;
    $('profileStrictness').value = profile.strictness || 'standard';
    $('profileWhitelist').value = (profile.whitelist || []).join('\n');
  }
  function renderPasswordState() {
    $('passwordState').textContent = state.passwordEnabled
      ? state.authToken ? 'Password protection is enabled; settings are unlocked for this session.' : 'Password protection is enabled; unlock before changing protected settings.'
      : 'Password protection is disabled.';
  }
  async function saveToggle(event) {
    const control = event.currentTarget;
    const key = control.dataset.setting;
    const before = state.settings[key];
    const value = control.type === 'checkbox' ? control.checked : control.value;
    try {
      await savePatch({ [key]: value });
      toast('Setting saved.');
    } catch (error) {
      if (control.type === 'checkbox') control.checked = before;
      else control.value = before;
      toast(error.message, true);
    }
  }
  async function savePatch(patch) {
    const response = await send('updateSettings', { settings: patch, authToken: state.authToken });
    state.settings = FSF.normalizeSettings(response.settings);
    state.config.settings = state.settings;
    state.config.listStatus = response.listStatus || state.config.listStatus;
    render();
  }
  function parseDomainInput(text) {
    const entries = [];
    const invalid = [];
    for (const raw of text.split(/\r?\n/)) {
      let line = raw.trim();
      if (!line || line.startsWith('#') || line.startsWith('!') || line.startsWith('//')) continue;
      const commentAt = line.search(/\s[#!]/);
      if (commentAt >= 0) line = line.slice(0, commentAt).trim();
      const parts = line.split(/\s+/);
      const hostsLine = parts.length > 1 && /^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)$/.test(parts[0]);
      const values = hostsLine ? parts.slice(1) : [parts[0]];
      if (!hostsLine && parts.length > 1) invalid.push(parts.slice(1).join(' '));
      for (const value of values) {
        const host = FSF.normalizeHost(value);
        if (host) entries.push(host);
        else invalid.push(value);
      }
    }
    return { entries: Array.from(new Set(entries)), invalid };
  }
  async function saveDomainList(key, fieldId, countId) {
    const result = parseDomainInput($(fieldId).value);
    if (result.invalid.length) return toast('Invalid domain entry: ' + result.invalid[0], true);
    try {
      await savePatch({ [key]: result.entries });
      $(countId).textContent = result.entries.length + ' domains';
      toast('Domain list saved.');
    } catch (error) { toast(error.message, true); }
  }
  async function clearList(key, fieldId) {
    if (!confirm('Clear this custom domain list?')) return;
    $(fieldId).value = '';
    await saveDomainList(key, fieldId, key === 'adultDomains' ? 'adultDomainCount' : 'phishingDomainCount');
  }
  function readListFile(event, key, fieldId) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) { toast('Text list exceeds the 2 MB size limit.', true); event.target.value = ''; return; }
    const reader = new FileReader();
    reader.onload = () => { $(fieldId).value = String(reader.result || ''); event.target.value = ''; toast('File loaded. Review it and choose Save to apply.'); };
    reader.onerror = () => { toast('Could not read the text file.', true); event.target.value = ''; };
    reader.readAsText(file);
  }
  async function saveKeywords() {
    const keywords = FSF.parseKeywordList($('customKeywords').value);
    try { await savePatch({ customKeywords: keywords }); toast('Keywords saved.'); }
    catch (error) { toast(error.message, true); }
  }
  async function addWhitelist(event) {
    event.preventDefault();
    const host = FSF.normalizeHost($('whitelistInput').value);
    if (!host) return toast('Enter a valid domain, such as example.com.', true);
    if (state.settings.whitelist.includes(host)) return toast('That domain is already whitelisted.', true);
    try {
      const response = await send('addWhitelist', { domain: host, authToken: state.authToken });
      state.settings = FSF.normalizeSettings(response.settings);
      state.config.settings = state.settings;
      $('whitelistInput').value = '';
      renderWhitelist();
      toast('Domain added to whitelist.');
    } catch (error) { toast(error.message, true); }
  }
  function renderWhitelist() {
    const list = $('whitelistList');
    list.replaceChildren();
    state.settings.whitelist.forEach(host => {
      const item = document.createElement('li');
      item.className = 'chip';
      const label = document.createElement('span');
      label.textContent = host;
      const remove = document.createElement('button');
      remove.type = 'button'; remove.textContent = 'Remove'; remove.setAttribute('aria-label', 'Remove ' + host + ' from whitelist');
      remove.addEventListener('click', async () => {
        try {
          const result = await send('removeWhitelist', { domain: host, authToken: state.authToken });
          state.settings = FSF.normalizeSettings(result.settings); state.config.settings = state.settings;
          renderWhitelist(); toast('Domain removed.');
        } catch (error) { toast(error.message, true); }
      });
      item.append(label, remove); list.appendChild(item);
    });
  }
  async function reloadLists() {
    try { const response = await send('reloadLists'); state.config.listStatus = response.listStatus; renderLists(); toast('List files reloaded.'); }
    catch (error) { toast(error.message, true); }
  }
  async function clearActivity() {
    if (!confirm('Permanently clear recent blocked activity?')) return;
    try { await send('clearActivity'); state.config.activity = []; renderActivity(); toast('Activity log cleared.'); }
    catch (error) { toast(error.message, true); }
  }
  async function pause(duration) {
    try {
      const response = await send('pause', { duration: duration === 'restart' ? 'restart' : Number(duration) });
      state.settings = FSF.normalizeSettings(response.settings); render(); toast('Protection paused.');
    } catch (error) { toast(error.message, true); }
  }
  async function resume() {
    try { const response = await send('resume'); state.settings = FSF.normalizeSettings(response.settings); render(); toast('Protection resumed.'); }
    catch (error) { toast(error.message, true); }
  }
  async function updateRemote() {
    try {
      await savePatch({
        remoteUpdates: $('remoteUpdates').checked,
        remoteAdultUrl: $('remoteAdultUrl').value.trim(),
        remotePhishingUrl: $('remotePhishingUrl').value.trim(),
        updateFrequencyHours: Number($('updateFrequencyHours').value)
      });
      const result = await send('updateRemote');
      state.config.listStatus = result.listStatus;
      state.config.remoteUpdatedAt = result.updatedAt;
      renderLists(); render();
      toast('Remote lists updated.');
    } catch (error) { toast(error.message, true); }
  }
  async function saveProfile() {
    const id = $('profileContainer').value;
    if (!id) return toast('Choose a Firefox container first.', true);
    const list = parseDomainInput($('profileWhitelist').value);
    if (list.invalid.length) return toast('Invalid profile whitelist domain: ' + list.invalid[0], true);
    const profiles = { ...state.settings.containerProfiles, [id]: {
      blockAdult: $('profileBlockAdult').checked,
      enforceSafeSearch: $('profileSafeSearch').checked,
      strictness: $('profileStrictness').value,
      whitelist: list.entries
    } };
    try { await savePatch({ containerProfiles: profiles }); toast('Container profile saved.'); }
    catch (error) { toast(error.message, true); }
  }
  async function unlock() {
    try {
      const result = await send('unlock', { password: $('currentPassword').value });
      state.authToken = result.authToken || '';
      $('currentPassword').value = '';
      renderPasswordState();
      toast('Protected settings unlocked.');
    } catch (error) { toast(error.message, true); }
  }
  async function setPassword() {
    try {
      const password = $('newPassword').value;
      const result = await send('setPassword', { password, authToken: state.authToken });
      state.authToken = result.authToken || '';
      state.passwordEnabled = true;
      $('newPassword').value = '';
      renderPasswordState();
      toast('Password protection enabled. Keep your password safe; it cannot be recovered.');
    } catch (error) { toast(error.message, true); }
  }
  async function removePassword() {
    if (!confirm('Remove password protection for sensitive settings?')) return;
    try { await send('removePassword', { authToken: state.authToken }); state.authToken = ''; state.passwordEnabled = false; renderPasswordState(); toast('Password protection removed.'); }
    catch (error) { toast(error.message, true); }
  }
  async function exportSettings() {
    try {
      const payload = { version: 2, settings: state.settings };
      const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }));
      const link = document.createElement('a'); link.href = url; link.download = 'blockem-settings.json'; link.click(); URL.revokeObjectURL(url);
      toast('Settings exported without password or activity data.');
    } catch (error) { toast(error.message, true); }
  }
  async function importSettings(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;
    if (file.size > 1024 * 1024) { toast('Settings file is too large.', true); event.target.value = ''; return; }
    try {
      const parsed = JSON.parse(await file.text());
      const incoming = parsed.settings || parsed;
      const normalized = FSF.normalizeSettings(incoming);
      const rawAdult = incoming.adultDomains || incoming.customBlocklist || [];
      const rawPhishing = incoming.phishingDomains || [];
      const adultValues = Array.isArray(rawAdult) ? rawAdult : String(rawAdult).split(/\r?\n/);
      const phishingValues = Array.isArray(rawPhishing) ? rawPhishing : String(rawPhishing).split(/\r?\n/);
      if (adultValues.some(value => typeof value !== 'string' || /\s/.test(value) || !FSF.normalizeHost(value))) throw new Error('Import contains an invalid adult domain.');
      if (phishingValues.some(value => typeof value !== 'string' || /\s/.test(value) || !FSF.normalizeHost(value))) throw new Error('Import contains an invalid phishing domain.');
      const result = await send('importSettings', { settings: normalized, authToken: state.authToken });
      state.settings = FSF.normalizeSettings(result.settings); state.config.settings = state.settings; state.config.listStatus = result.listStatus || state.config.listStatus;
      render(); toast('Settings imported.');
    } catch (error) { toast(error.message || 'Import file is invalid.', true); }
    finally { event.target.value = ''; }
  }
  async function resetDefaults() {
    if (!confirm('Reset all settings and custom lists to their safe defaults? Your password and activity log are retained.')) return;
    try { await savePatch({ ...FSF.DEFAULT_SETTINGS }); toast('Settings reset to defaults.'); }
    catch (error) { toast(error.message, true); }
  }
  let toastTimer;
  function toast(message, error) {
    const element = $('toast');
    element.textContent = message;
    element.className = 'toast' + (error ? ' error' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { element.className = 'toast hidden'; }, error ? 6000 : 3500);
  }
})();

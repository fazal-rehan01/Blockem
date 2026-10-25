(function () {
  'use strict';

  const api = browser;
  const MAX_LIST_BYTES = 2 * 1024 * 1024;
  const UPDATE_ALARM = 'blockem-list-update';
  const PAUSE_ALARM = 'blockem-pause-expiry';
  const ACTIVITY_LIMIT = 20;
  const PASSWORD_TTL = 10 * 60 * 1000;
  const SAFE_SEARCH = [
    { host: /^google\.[a-z.]+$/, path: /^\/search\/?$/, key: 'safe', value: 'active' },
    { host: /(?:^|\.)bing\.com$/, path: /^\/(?:(?:images|videos|news)\/)?search\/?$/, key: 'adlt', value: 'strict' },
    { host: /(?:^|\.)duckduckgo\.com$/, path: /^.*$/, key: 'kp', value: '1' },
    { host: /^search\.brave\.com$/, path: /^\/search\/?$/, key: 'safesearch', value: 'strict' }
  ];

  let settings = FSF.normalizeSettings();
  let passwordRecord = null;
  let authToken = null;
  let authExpires = 0;
  let adultDomains = new Set();
  let phishingDomains = new Set();
  let keywords = [];
  let keywordRegex = null;
  let listStatus = { adult: 0, phishing: 0, keywords: 0, errors: [] };
  let initPromise;
  let activityWrite = Promise.resolve();

  const storageGet = async keys => {
    try { return await api.storage.local.get(keys); }
    catch (error) { console.warn('[Blockem] Local settings could not be read:', error); return {}; }
  };
  const saveSettings = async () => api.storage.local.set({ settings });
  const fail = message => { throw new Error(message); };

  function matchesSet(host, entries) {
    for (const entry of entries) if (FSF.hostMatches(host, entry)) return true;
    return false;
  }

  function profileFor(details) {
    if (!settings.containerProfilesEnabled || !details.cookieStoreId) return settings;
    const profile = settings.containerProfiles[details.cookieStoreId];
    if (!profile || typeof profile !== 'object') return settings;
    return { ...settings, ...profile, whitelist: FSF.normalizeHostList(profile.whitelist) };
  }

  function normalizedKeywords(prefs) {
    return Array.from(new Set([
      ...(FSF.DEFAULT_KEYWORDS[prefs.strictness] || FSF.DEFAULT_KEYWORDS.standard),
      ...keywords,
      ...prefs.customKeywords
    ]));
  }

  async function loadTextFile(path) {
    const response = await fetch(api.runtime.getURL(path), { cache: 'no-store' });
    if (!response.ok) throw new Error(path + ' returned HTTP ' + response.status);
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_LIST_BYTES) throw new Error(path + ' exceeds the size limit.');
    return text;
  }

  async function reloadLists() {
    const errors = [];
    const paths = FSF.BLOCKLIST_FILES;
    const [adultText, phishingText, keywordText] = await Promise.all([
      loadTextFile(paths.adult).catch(error => { errors.push(error.message); return ''; }),
      loadTextFile(paths.phishing).catch(error => { errors.push(error.message); return ''; }),
      loadTextFile(paths.keywords).catch(error => { errors.push(error.message); return ''; })
    ]);
    adultDomains = new Set([...FSF.parseDomainList(adultText), ...settings.adultDomains]);
    phishingDomains = new Set([...FSF.parseDomainList(phishingText), ...settings.phishingDomains]);
    keywords = FSF.parseKeywordList(keywordText);
    keywordRegex = FSF.buildKeywordRegex(normalizedKeywords(settings));
    listStatus = { adult: adultDomains.size, phishing: phishingDomains.size, keywords: normalizedKeywords(settings).length, errors };
    if (settings.remoteUpdates) {
      const cache = await storageGet(['remoteAdult', 'remotePhishing']);
      for (const domain of cache.remoteAdult || []) adultDomains.add(domain);
      for (const domain of cache.remotePhishing || []) phishingDomains.add(domain);
    }
    listStatus.adult = adultDomains.size;
    listStatus.phishing = phishingDomains.size;
    return listStatus;
  }

  function getSafeSearchRedirect(url) {
    const host = url.hostname.toLowerCase().replace(/^www\./, '');
    for (const engine of SAFE_SEARCH) {
      if (!engine.host.test(host) || !engine.path.test(url.pathname)) continue;
      if (url.searchParams.get(engine.key) === engine.value) return null;
      url.searchParams.set(engine.key, engine.value);
      return url.href;
    }
    return null;
  }

  function recordBlock(hostname, reason) {
    const host = FSF.normalizeHost(hostname);
    if (!host) return;
    activityWrite = activityWrite.then(async () => {
      const { activity } = await api.storage.local.get({ activity: [] });
      const rows = Array.isArray(activity) ? activity : [];
      const previous = rows[0];
      const now = Date.now();
      if (previous && previous.hostname === host && previous.reason === reason && now - previous.timestamp < 60_000) return;
      rows.unshift({ hostname: host, reason, timestamp: now });
      await api.storage.local.set({ activity: rows.slice(0, ACTIVITY_LIMIT) });
    }).catch(error => console.warn('[Blockem] Could not save activity:', error));
  }

  function responseFor(details, reason, hostname) {
    recordBlock(hostname, reason);
    if (details.type !== 'main_frame') return { cancel: true };
    const target = api.runtime.getURL('blocked.html') + '?reason=' + encodeURIComponent(reason)
      + '&host=' + encodeURIComponent(FSF.normalizeHost(hostname) || 'unknown');
    return { redirectUrl: target };
  }

  function inspectResponse(details) {
    if (!settings.responseScanning || details.type !== 'main_frame' || typeof api.webRequest.filterResponseData !== 'function') return;
    let filter;
    try { filter = api.webRequest.filterResponseData(details.requestId); }
    catch (error) { console.warn('[Blockem] Response inspection unavailable:', error); return; }
    const decoder = new TextDecoder();
    let tail = '';
    let scannedBytes = 0;
    const maxScan = 10 * 1024 * 1024;
    filter.ondata = event => {
      try {
        scannedBytes += event.data.byteLength;
        if (scannedBytes <= maxScan) {
          const text = tail + decoder.decode(event.data, { stream: true });
          for (const blockedHost of [...adultDomains, ...phishingDomains]) {
            const escaped = blockedHost.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            if (new RegExp('(?:^|[^a-z0-9.-])' + escaped + '(?=$|[^a-z0-9.-])', 'i').test(text)) {
              console.info('[Blockem] Strict response inspection found a configured blocked-domain reference:', blockedHost);
              break;
            }
          }
          tail = text.slice(-300);
        }
        filter.write(event.data);
      } catch (error) {
        console.warn('[Blockem] Response inspection failed; closing the stream:', error);
        try { filter.disconnect(); } catch (_) { try { filter.close(); } catch (ignored) {} }
      }
    };
    filter.onstop = () => {
      try { decoder.decode(); filter.close(); } catch (error) { console.warn('[Blockem] Could not close response stream:', error); }
    };
    filter.onerror = () => {
      try { filter.disconnect(); } catch (_) { try { filter.close(); } catch (ignored) {} }
    };
  }

  function handleBeforeRequest(details) {
    if (!/^https?:/i.test(details.url)) return {};
    let url;
    try { url = new URL(details.url); } catch (_) { return {}; }
    const host = FSF.normalizeHost(url.hostname);
    if (!host) return {};
    const prefs = profileFor(details);

    const paused = settings.pauseUntil === -1 || settings.pauseUntil > Date.now();
    if (paused) return {};
    if (FSF.isWhitelisted(host, prefs.whitelist)) return {};

    if (prefs.enforceSafeSearch && (details.type === 'main_frame' || details.type === 'sub_frame')) {
      const safe = getSafeSearchRedirect(url);
      if (safe) return { redirectUrl: safe };
    }

    if (!paused && prefs.blockPhishing && matchesSet(host, phishingDomains)) return responseFor(details, 'phishing', host);
    if (!paused && prefs.blockAdult && matchesSet(host, adultDomains)) return responseFor(details, 'adult', host);

    if (!paused && details.type === 'main_frame' && prefs.blockAdult && prefs.keywordFiltering !== false) {
      const activeRegex = FSF.buildKeywordRegex(normalizedKeywords(prefs));
      if (FSF.matchesKeyword(details.url, activeRegex)) return responseFor(details, 'keyword', host);
    }
    return {};
  }

  function handleResponseHeaders(details) {
    if (!settings.responseScanning || details.type !== 'main_frame' || settings.pauseUntil === -1 || settings.pauseUntil > Date.now()) return {};
    const headers = details.responseHeaders || [];
    const contentType = headers.find(header => header.name.toLowerCase() === 'content-type');
    if (!contentType || !/^text\/html(?:\s*;|$)/i.test(contentType.value || '')) return {};
    inspectResponse(details);
    return {};
  }

  function authorized(token) {
    return !passwordRecord || (typeof token === 'string' && token === authToken && Date.now() < authExpires);
  }

  function isSensitive(patch) {
    return ['blockAdult', 'blockPhishing', 'strictness', 'adultDomains', 'customBlocklist', 'phishingDomains', 'whitelist', 'customKeywords', 'containerProfiles']
      .some(key => Object.prototype.hasOwnProperty.call(patch, key));
  }

  async function updateSettings(patch, token) {
    if (!patch || typeof patch !== 'object') fail('Invalid settings.');
    if (isSensitive(patch) && !authorized(token)) fail('Unlock protected settings in the dashboard first.');
    const next = FSF.normalizeSettings({ ...settings, ...patch });
    settings = next;
    await saveSettings();
    if (!settings.remoteUpdates) await api.storage.local.remove(['remoteAdult', 'remotePhishing', 'remoteUpdatedAt']);
    await reloadLists();
    await scheduleUpdate();
    await schedulePause();
    return settings;
  }

  function validateRemoteUrl(value) {
    if (!value) return '';
    let url;
    try { url = new URL(value); } catch (_) { fail('Remote list URLs must be valid HTTP or HTTPS URLs.'); }
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) fail('Remote list URLs must be HTTP or HTTPS without credentials.');
    return url.href;
  }

  async function fetchRemoteList(url) {
    if (!url) return [];
    const response = await fetch(url, { cache: 'no-store', credentials: 'omit', redirect: 'error' });
    if (!response.ok) fail('List download returned HTTP ' + response.status + '.');
    const length = Number(response.headers.get('content-length') || 0);
    if (length > MAX_LIST_BYTES) fail('Downloaded list exceeds the 2 MB size limit.');
    let bytes;
    if (response.body && response.body.getReader) {
      const reader = response.body.getReader();
      const chunks = [];
      let total = 0;
      try {
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          total += part.value.byteLength;
          if (total > MAX_LIST_BYTES) {
            await reader.cancel();
            fail('Downloaded list exceeds the 2 MB size limit.');
          }
          chunks.push(part.value);
        }
      } finally {
        reader.releaseLock();
      }
      bytes = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    } else {
      const data = await response.arrayBuffer();
      if (data.byteLength > MAX_LIST_BYTES) fail('Downloaded list exceeds the 2 MB size limit.');
      bytes = new Uint8Array(data);
    }
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch (_) { fail('Downloaded list is not valid UTF-8 text.'); }
    const invalidLines = [];
    for (const rawLine of text.split(/\r?\n/)) {
      let line = rawLine.trim();
      if (!line || line.startsWith('#') || line.startsWith('!') || line.startsWith('//')) continue;
      const commentAt = line.search(/\s[#!]/);
      if (commentAt >= 0) line = line.slice(0, commentAt).trim();
      const parts = line.split(/\s+/);
      const values = parts.length > 1 && /^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)$/.test(parts[0]) ? parts.slice(1) : [parts[0]];
      if (!values.length || values.some(value => !FSF.normalizeHost(value))) invalidLines.push(rawLine);
    }
    const parsed = FSF.parseDomainList(text);
    if (invalidLines.length) fail('Downloaded list contains invalid domain entries.');
    if (text.trim() && !parsed.length) fail('Downloaded list contains no valid domains.');
    return parsed;
  }

  async function updateRemoteLists() {
    if (!settings.remoteUpdates) return;
    const adultUrl = validateRemoteUrl(settings.remoteAdultUrl);
    const phishingUrl = validateRemoteUrl(settings.remotePhishingUrl);
    const [remoteAdult, remotePhishing] = await Promise.all([
      fetchRemoteList(adultUrl), fetchRemoteList(phishingUrl)
    ]);
    await api.storage.local.set({ remoteAdult, remotePhishing, remoteUpdatedAt: Date.now() });
    await reloadLists();
  }

  async function scheduleUpdate() {
    await api.alarms.clear(UPDATE_ALARM);
    if (settings.remoteUpdates) {
      await api.alarms.create(UPDATE_ALARM, { periodInMinutes: settings.updateFrequencyHours * 60 });
    }
  }

  async function schedulePause() {
    await api.alarms.clear(PAUSE_ALARM);
    if (settings.pauseUntil > Date.now()) {
      await api.alarms.create(PAUSE_ALARM, { when: settings.pauseUntil });
    }
  }

  async function load() {
    if (initPromise) return initPromise;
    initPromise = (async () => {
      const data = await storageGet(['settings', 'passwordRecord']);
      settings = FSF.normalizeSettings(data.settings);
      passwordRecord = data.passwordRecord || null;
      if (settings.pauseUntil === -1) {
        settings.pauseUntil = 0;
        await saveSettings();
      }
      await reloadLists();
      await schedulePause();
      await scheduleUpdate();
    })().catch(error => console.error('[Blockem] Initialization failed:', error));
    return initPromise;
  }

  function bytesToHex(bytes) { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
  function hexToBytes(hex) {
    if (typeof hex !== 'string' || !/^(?:[a-f0-9]{2})+$/i.test(hex)) return null;
    return new Uint8Array(hex.match(/.{2}/g).map(pair => parseInt(pair, 16)));
  }
  async function passwordHash(password, salt) {
    if (typeof password !== 'string' || password.length < 8 || password.length > 1024) fail('Use a password between 8 and 1024 characters.');
    const material = new TextEncoder().encode(password);
    const saltBytes = salt ? hexToBytes(salt) : crypto.getRandomValues(new Uint8Array(16));
    if (!saltBytes) fail('Password record is invalid.');
    const data = new Uint8Array(saltBytes.length + material.length);
    data.set(saltBytes); data.set(material, saltBytes.length);
    return { salt: bytesToHex(saltBytes), hash: bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', data))) };
  }
  async function verifyPassword(password) {
    if (!passwordRecord) return true;
    const result = await passwordHash(password, passwordRecord.salt);
    if (result.hash.length !== passwordRecord.hash.length) return false;
    let difference = 0;
    for (let index = 0; index < result.hash.length; index += 1) difference |= result.hash.charCodeAt(index) ^ passwordRecord.hash.charCodeAt(index);
    return difference === 0;
  }

  async function dispatch(message) {
    await load();
    switch (message.action) {
      case 'getConfig': {
        const data = await storageGet(['activity', 'remoteUpdatedAt']);
        let profileIdentities = [];
        try { profileIdentities = await api.contextualIdentities.query({}); } catch (_) {}
        return { settings, listStatus, passwordEnabled: Boolean(passwordRecord), activity: data.activity || [], remoteUpdatedAt: data.remoteUpdatedAt || 0, profileIdentities, keywords };
      }
      case 'checkSiteStatus': {
        const host = FSF.normalizeHost(message.hostname);
        if (!host) return { status: 'allowed' };
        if (settings.pauseUntil === -1 || settings.pauseUntil > Date.now()) return { status: 'allowed' };
        const prefs = profileFor({ cookieStoreId: message.cookieStoreId });
        if (FSF.isWhitelisted(host, prefs.whitelist)) return { status: 'whitelisted' };
        if (prefs.blockPhishing && matchesSet(host, phishingDomains)) return { status: 'blocked', reason: 'phishing' };
        if (prefs.blockAdult && matchesSet(host, adultDomains)) return { status: 'blocked', reason: 'adult' };
        return { status: 'allowed' };
      }
      case 'updateSettings':
        return { ok: true, settings: await updateSettings(message.settings, message.authToken), listStatus };
      case 'reloadLists':
        return { ok: true, listStatus: await reloadLists() };
      case 'addWhitelist':
      case 'removeWhitelist': {
        if (!authorized(message.authToken)) fail('Unlock protected settings in the dashboard first.');
        const host = FSF.normalizeHost(message.domain);
        if (!host) fail('Enter a valid domain.');
        const list = new Set(settings.whitelist);
        if (message.action === 'addWhitelist') list.add(host); else list.delete(host);
        settings.whitelist = Array.from(list);
        await saveSettings();
        await reloadLists();
        return { ok: true, settings, listStatus };
      }
      case 'clearActivity':
        await api.storage.local.set({ activity: [] });
        return { ok: true };
      case 'getActivity': {
        const data = await storageGet(['activity']);
        return { ok: true, activity: data.activity || [] };
      }
      case 'pause': {
        const duration = message.duration;
        settings.pauseUntil = duration === 'restart' ? -1 : Date.now() + (duration === 15 ? 15 : 60) * 60 * 1000;
        await saveSettings(); await schedulePause();
        return { ok: true, settings };
      }
      case 'resume':
        settings.pauseUntil = 0; await saveSettings(); await schedulePause(); return { ok: true, settings };
      case 'unlock': {
        if (!passwordRecord) return { ok: true, authToken: '' };
        if (!await verifyPassword(message.password)) fail('Password is incorrect.');
        authToken = bytesToHex(crypto.getRandomValues(new Uint8Array(24)));
        authExpires = Date.now() + PASSWORD_TTL;
        return { ok: true, authToken };
      }
      case 'setPassword': {
        if (passwordRecord && !authorized(message.authToken)) fail('Unlock protected settings before changing the password.');
        const record = await passwordHash(message.password);
        passwordRecord = record;
        await api.storage.local.set({ passwordRecord });
        authToken = bytesToHex(crypto.getRandomValues(new Uint8Array(24)));
        authExpires = Date.now() + PASSWORD_TTL;
        return { ok: true, authToken };
      }
      case 'removePassword':
        if (!authorized(message.authToken)) fail('Unlock protected settings before removing password protection.');
        passwordRecord = null; authToken = null; authExpires = 0;
        await api.storage.local.remove('passwordRecord'); return { ok: true };
      case 'updateRemote':
        if (!settings.remoteUpdates) fail('Enable optional remote updates before downloading lists.');
        await updateRemoteLists(); return { ok: true, listStatus, updatedAt: Date.now() };
      case 'importSettings':
        return { ok: true, settings: await updateSettings(FSF.normalizeSettings(message.settings), message.authToken), listStatus };
      default: fail('Unknown request.');
    }
  }

  api.webRequest.onBeforeRequest.addListener(handleBeforeRequest, { urls: ['http://*/*', 'https://*/*'] }, ['blocking']);
  api.webRequest.onHeadersReceived.addListener(handleResponseHeaders, { urls: ['http://*/*', 'https://*/*'] }, ['blocking', 'responseHeaders']);
  api.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.settings) {
      settings = FSF.normalizeSettings(changes.settings.newValue);
      void reloadLists();
    }
  });
  api.runtime.onMessage.addListener(message => dispatch(message).catch(error => ({ ok: false, error: error.message || 'Request failed.' })));
  api.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === UPDATE_ALARM && settings.remoteUpdates) updateRemoteLists().catch(error => console.warn('[Blockem] Remote update failed:', error.message));
    if (alarm.name === PAUSE_ALARM && settings.pauseUntil > 0 && settings.pauseUntil <= Date.now()) {
      settings.pauseUntil = 0; saveSettings().catch(error => console.warn('[Blockem] Could not resume protection:', error));
    }
  });
  api.runtime.onStartup.addListener(() => load());
  api.runtime.onInstalled.addListener(() => load());
  void load();
})();

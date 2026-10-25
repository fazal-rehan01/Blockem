(function (global) {
  'use strict';

  const DEFAULT_KEYWORDS = Object.freeze({
    relaxed: ['porn', 'pornography', 'nsfw', 'xxx', 'nude', 'nudity', 'hentai'],
    standard: ['porn', 'pornography', 'nsfw', 'xxx', 'nude', 'nudity', 'hentai', 'erotic', 'sexcam', 'escort', 'adult'],
    strict: ['porn', 'pornography', 'nsfw', 'xxx', 'nude', 'nudity', 'hentai', 'erotic', 'erotica', 'sexcam', 'escort', 'adult', 'sexual', 'fetish', 'milf', 'lewd']
  });
  const DEFAULT_SETTINGS = Object.freeze({
    blockAdult: true,
    blockPhishing: true,
    enforceSafeSearch: true,
    keywordFiltering: true,
    scanContent: true,
    dynamicFiltering: true,
    strictness: 'standard',
    adultDomains: [],
    phishingDomains: [],
    customBlocklist: [],
    customKeywords: [],
    whitelist: [],
    pauseUntil: 0,
    remoteUpdates: false,
    remoteAdultUrl: '',
    remotePhishingUrl: '',
    updateFrequencyHours: 24,
    responseScanning: false,
    containerProfilesEnabled: false,
    containerProfiles: {}
  });
  const BLOCKLIST_FILES = Object.freeze({
    adult: 'blocklists/adult-domains.txt',
    phishing: 'blocklists/phishing-malicious.txt',
    keywords: 'blocklists/nsfw-keywords.txt'
  });

  function normalizeHost(value) {
    if (typeof value !== 'string') return null;
    let text = value.trim().toLowerCase();
    if (!text || text.startsWith('#')) return null;
    text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
    text = text.replace(/^\|\|?/, '').replace(/\^+$/, '');
    text = text.split(/[/?#\s]/)[0].replace(/:\d+$/, '').replace(/^\*\./, '');
    text = text.replace(/^\.+|\.+$/g, '');
    try {
      const parsed = new URL('http://' + text);
      let host = parsed.hostname.toLowerCase();
      if (host.startsWith('www.')) host = host.slice(4);
      if (!host || host.length > 253 || !/^[a-z0-9.-]+$/.test(host)) return null;
      const labels = host.split('.');
      if (labels.some(label => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return null;
      return host;
    } catch (_) {
      return null;
    }
  }

  function parseDomainList(text) {
    if (typeof text !== 'string') return [];
    const domains = new Set();
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#') || line.startsWith('!') || line.startsWith('//')) continue;
      const parts = line.split(/\s+/);
      const values = parts.length > 1 && /^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)$/.test(parts[0]) ? parts.slice(1) : [parts[0]];
      for (const value of values) {
        const domain = normalizeHost(value);
        if (domain) domains.add(domain);
      }
    }
    return Array.from(domains);
  }

  function normalizeHostList(value) {
    const list = Array.isArray(value) ? value : typeof value === 'string' ? parseDomainList(value) : [];
    return Array.from(new Set(list.map(normalizeHost).filter(Boolean)));
  }

  function parseKeywordList(text) {
    if (Array.isArray(text)) text = text.join('\n');
    if (typeof text !== 'string') return [];
    return Array.from(new Set(text.split(/[\r\n,]+/).map(word => word.trim().toLowerCase()).filter(word => word && word.length <= 80)));
  }

  function normalizeSettings(raw) {
    const source = raw && typeof raw === 'object' ? raw : {};
    const strictness = ['relaxed', 'standard', 'strict'].includes(source.strictness) ? source.strictness : 'standard';
    const adultDomains = normalizeHostList(source.adultDomains || source.customBlocklist);
    const profiles = {};
    if (source.containerProfiles && typeof source.containerProfiles === 'object' && !Array.isArray(source.containerProfiles)) {
      for (const [id, rawProfile] of Object.entries(source.containerProfiles)) {
        if (!rawProfile || typeof rawProfile !== 'object' || !/^[a-z0-9_-]{1,100}$/i.test(id)) continue;
        profiles[id] = {
          blockAdult: rawProfile.blockAdult !== false,
          enforceSafeSearch: rawProfile.enforceSafeSearch !== false,
          strictness: ['relaxed', 'standard', 'strict'].includes(rawProfile.strictness) ? rawProfile.strictness : 'standard',
          whitelist: normalizeHostList(rawProfile.whitelist)
        };
      }
    }
    return {
      blockAdult: source.blockAdult !== false,
      blockPhishing: source.blockPhishing !== false,
      enforceSafeSearch: source.enforceSafeSearch !== false,
      keywordFiltering: source.keywordFiltering !== false,
      scanContent: source.scanContent !== false,
      dynamicFiltering: source.dynamicFiltering !== false,
      strictness,
      adultDomains,
      phishingDomains: normalizeHostList(source.phishingDomains),
      customBlocklist: adultDomains,
      customKeywords: parseKeywordList(source.customKeywords || []),
      whitelist: normalizeHostList(source.whitelist),
      pauseUntil: Number.isFinite(Number(source.pauseUntil)) ? Number(source.pauseUntil) : 0,
      remoteUpdates: source.remoteUpdates === true,
      remoteAdultUrl: typeof source.remoteAdultUrl === 'string' ? source.remoteAdultUrl.trim() : '',
      remotePhishingUrl: typeof source.remotePhishingUrl === 'string' ? source.remotePhishingUrl.trim() : '',
      updateFrequencyHours: Math.max(1, Math.min(720, Number(source.updateFrequencyHours) || 24)),
      responseScanning: source.responseScanning === true,
      containerProfilesEnabled: source.containerProfilesEnabled === true,
      containerProfiles: profiles
    };
  }

  function isIpHost(host) {
    return host.includes(':') || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
  }

  function hostMatches(host, entry) {
    const h = normalizeHost(host), e = normalizeHost(entry);
    return Boolean(h && e && (h === e || (!isIpHost(e) && h.endsWith('.' + e))));
  }

  function isWhitelisted(host, list) {
    return Array.isArray(list) && list.some(entry => hostMatches(host, entry));
  }

  function normalizeKeywordText(text) {
    let value = String(text == null ? '' : text).toLowerCase();
    try { value = decodeURIComponent(value); } catch (_) {}
    return value.replace(/[_+-]+/g, ' ').replace(/%20/g, ' ').replace(/\s+/g, ' ');
  }

  function buildKeywordRegex(keywords) {
    const list = parseKeywordList(keywords || []);
    if (!list.length) return null;
    const escaped = list.sort((a, b) => b.length - a.length)
      .map(word => word.split(/\s+/).map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('\\s+'));
    return new RegExp('(?:^|[^a-z0-9])(?:' + escaped.join('|') + ')(?=$|[^a-z0-9])', 'i');
  }

  function matchesKeyword(text, regex) {
    if (!regex) return false;
    regex.lastIndex = 0;
    return regex.test(normalizeKeywordText(text));
  }

  global.FSF = Object.freeze({
    BLOCKLIST_FILES, DEFAULT_KEYWORDS, DEFAULT_SETTINGS, buildKeywordRegex, hostMatches,
    isIpHost, isWhitelisted, matchesKeyword, normalizeHost, normalizeHostList,
    normalizeSettings, parseDomainList, parseKeywordList
  });
})(globalThis);

(function () {
  const stateByTab = new Map();

  const FINGERPRINT_TECHNIQUES = {
    canvas: ["canvas.toDataURL", "canvas.getImageData"],
    webgl: ["webgl.getParameter", "webgl.WEBGL_debug_renderer_info"],
    audio: ["audio.createOscillator", "audio.createDynamicsCompressor"]
  };

  function ensureTabState(tabId) {
    if (!stateByTab.has(tabId)) {
      stateByTab.set(tabId, {
        tabId,
        tabUrl: "",
        firstPartyDomain: "",
        requests: [],
        thirdPartyDomains: new Set(),
        suspiciousScripts: [],
        redirectEvents: [],
        storageSummary: {
          localStorage: { keys: [], estimatedBytes: 0 },
          sessionStorage: { keys: [], estimatedBytes: 0 },
          indexedDB: { databases: [], estimatedBytes: 0, inaccessible: false }
        },
        cookiesSummary: {
          all: [],
          firstParty: [],
          thirdParty: [],
          session: [],
          persistent: []
        },
        supercookieSignals: {
          hstsHeuristic: false,
          etagTrackingCandidates: []
        },
        fingerprintingEvents: [],
        responseEtags: new Map()
      });
    }
    return stateByTab.get(tabId);
  }

  function safeUrl(url) {
    try {
      return new URL(url);
    } catch (_err) {
      return null;
    }
  }

  function getRegistrableDomain(hostname) {
    if (!hostname) return "";
    const parts = hostname.split(".").filter(Boolean);
    if (parts.length <= 2) return hostname;
    const tld = parts[parts.length - 1];
    const sld = parts[parts.length - 2];
    if (tld.length === 2 && parts.length >= 3) {
      const maybeCcSld = parts[parts.length - 3];
      const commonCcSlds = new Set(["com", "org", "net", "gov", "edu", "co"]);
      if (commonCcSlds.has(sld)) {
        return `${maybeCcSld}.${sld}.${tld}`;
      }
    }
    return `${sld}.${tld}`;
  }

  function getSecondLevelLabel(hostname) {
    const reg = getRegistrableDomain(hostname);
    const parts = reg.split(".").filter(Boolean);
    if (parts.length < 2) return "";
    return parts[parts.length - 2];
  }

  function isSameBrandDomain(hostA, hostB) {
    const a = getSecondLevelLabel(hostA);
    const b = getSecondLevelLabel(hostB);
    if (!a || !b) return false;
    return a === b;
  }

  function isThirdParty(pageUrl, reqUrl) {
    const p = safeUrl(pageUrl);
    const r = safeUrl(reqUrl);
    if (!p || !r) return false;
    const pReg = getRegistrableDomain(p.hostname);
    const rReg = getRegistrableDomain(r.hostname);
    if (pReg && rReg && pReg === rReg) return false;
    if (isSameBrandDomain(p.hostname, r.hostname)) return false;
    return pReg && rReg ? pReg !== rReg : p.hostname !== r.hostname;
  }

  function classifyScriptSuspicious(pageUrl, reqUrl) {
    const p = safeUrl(pageUrl);
    const r = safeUrl(reqUrl);
    if (!p || !r) return false;
    if (!isThirdParty(pageUrl, reqUrl)) return false;

    const pageDomain = getRegistrableDomain(p.hostname);
    const reqDomain = getRegistrableDomain(r.hostname);

    if (reqDomain.endsWith(pageDomain)) return false;

    const knownInfra = [
      "cloudflare",
      "akamai",
      "fastly",
      "jsdelivr",
      "unpkg",
      "cloudfront",
      "cdn",
      "static",
      "assets"
    ];
    if (knownInfra.some((k) => reqDomain.includes(k))) return false;

    const knownVendors = [
      "googletagmanager",
      "google-analytics",
      "googlesyndication",
      "doubleclick",
      "gstatic",
      "facebook",
      "fbcdn",
      "newrelic",
      "datadoghq",
      "segment",
      "mixpanel",
      "hotjar",
      "clarity",
      "tiktok",
      "pinterest",
      "reddit",
      "adsrvr",
      "bing",
      "amazon-adsystem",
      "singular",
      "mpulse"
    ];
    return !knownVendors.some((k) => reqDomain.includes(k));
  }

  async function updateTabUrl(tabId) {
    if (tabId < 0) return;
    try {
      const tab = await browser.tabs.get(tabId);
      const s = ensureTabState(tabId);
      s.tabUrl = tab.url || s.tabUrl || "";
      const u = safeUrl(s.tabUrl);
      s.firstPartyDomain = u ? getRegistrableDomain(u.hostname) : "";
    } catch (_err) {
      // Ignore inaccessible tabs.
    }
  }

  function computeScore(snapshot) {
    let score = 100;
    const breakdown = [];

    const thirdPartyDomainCount = snapshot.thirdPartyConnections.length;
    const tpPenalty = Math.max(-30, -3 * thirdPartyDomainCount);
    score += tpPenalty;
    breakdown.push({ label: "Dominios de 3a parte", value: tpPenalty });

    const techniquesUsed = new Set();
    for (const ev of snapshot.fingerprintingEvents) {
      if (FINGERPRINT_TECHNIQUES.canvas.includes(ev.api)) techniquesUsed.add("canvas");
      if (FINGERPRINT_TECHNIQUES.webgl.includes(ev.api)) techniquesUsed.add("webgl");
      if (FINGERPRINT_TECHNIQUES.audio.includes(ev.api)) techniquesUsed.add("audio");
    }
    const fpPenalty = -20 * techniquesUsed.size;
    score += fpPenalty;
    breakdown.push({ label: "Fingerprinting", value: fpPenalty });

    const thirdPartyCookieCount = snapshot.cookiesSummary.thirdParty.length;
    const cookiePenalty = Math.max(-15, -5 * thirdPartyCookieCount);
    score += cookiePenalty;
    breakdown.push({ label: "Cookies de 3a parte", value: cookiePenalty });

    const suspiciousPenalty = Math.max(-30, -3 * snapshot.suspiciousScripts.length);
    score += suspiciousPenalty;
    breakdown.push({ label: "Scripts suspeitos", value: suspiciousPenalty });

    const hasStorageData =
      snapshot.storageSummary.localStorage.keys.length > 0 ||
      snapshot.storageSummary.sessionStorage.keys.length > 0 ||
      snapshot.storageSummary.indexedDB.databases.length > 0;
    const storagePenalty = hasStorageData ? -5 : 0;
    score += storagePenalty;
    breakdown.push({ label: "Web Storage/IndexedDB", value: storagePenalty });

    score = Math.max(0, Math.min(100, score));

    let band = "Verde (seguro)";
    if (score < 50) band = "Vermelho (critico)";
    else if (score < 80) band = "Amarelo (moderado)";

    return { value: score, band, breakdown };
  }

  async function buildSnapshot(tabId) {
    await updateTabUrl(tabId);
    const s = ensureTabState(tabId);

    const thirdPartyConnections = Array.from(s.thirdPartyDomains).map((domain) => {
      const types = s.requests.filter((r) => r.domain === domain).map((r) => r.type);
      const uniqueTypes = Array.from(new Set(types));
      return { domain, resourceTypes: uniqueTypes, count: types.length };
    });

    const snapshot = {
      tabId,
      tabUrl: s.tabUrl,
      firstPartyDomain: s.firstPartyDomain,
      thirdPartyConnections,
      suspiciousScripts: s.suspiciousScripts,
      redirectEvents: s.redirectEvents,
      storageSummary: s.storageSummary,
      cookiesSummary: s.cookiesSummary,
      supercookieSignals: {
        hstsHeuristic: s.supercookieSignals.hstsHeuristic,
        etagTrackingCandidates: s.supercookieSignals.etagTrackingCandidates
      },
      fingerprintingEvents: s.fingerprintingEvents
    };

    snapshot.privacyScore = computeScore(snapshot);
    return snapshot;
  }

  async function refreshCookies(tabId) {
    if (tabId < 0) return;
    await updateTabUrl(tabId);
    const s = ensureTabState(tabId);
    const tabUrl = safeUrl(s.tabUrl);
    if (!tabUrl || !tabUrl.hostname) return;

    const cookies = await browser.cookies.getAll({ url: tabUrl.href });
    // Para cookies de terceira parte associados as requisicoes feitas, precisariamos buscar por dominio
    // Mas para simplificar e focar apenas na aba atual, pegaremos todos e filtraremos
    const allCookies = await browser.cookies.getAll({});
    
    const firstParty = [];
    const thirdParty = [];
    const session = [];
    const persistent = [];

    const tabRegDomain = getRegistrableDomain(tabUrl.hostname);
    const contactedDomains = new Set(Array.from(s.thirdPartyDomains).map(getRegistrableDomain));
    contactedDomains.add(tabRegDomain);

    const relevantCookies = allCookies.filter(ck => {
      const cookieRegDomain = getRegistrableDomain((ck.domain || "").replace(/^\./, ""));
      return contactedDomains.has(cookieRegDomain);
    });

    for (const ck of relevantCookies) {
      const cookieDomain = (ck.domain || "").replace(/^\./, "");
      const row = {
        name: ck.name,
        domain: ck.domain,
        path: ck.path,
        session: ck.session,
        expirationDate: ck.expirationDate || null
      };

      const sameParty = getRegistrableDomain(cookieDomain) === tabRegDomain;
      if (sameParty) firstParty.push(row);
      else thirdParty.push(row);

      if (ck.session) session.push(row);
      else persistent.push(row);
    }

    s.cookiesSummary = {
      all: relevantCookies.map((c) => ({
        name: c.name,
        domain: c.domain,
        path: c.path,
        session: c.session,
        expirationDate: c.expirationDate || null
      })),
      firstParty,
      thirdParty,
      session,
      persistent
    };
  }

  function trackHstsHeuristic(tabState, reqDetails) {
    const u = safeUrl(reqDetails.url);
    if (!u) return;
    if (u.protocol === "https:") {
      const hadHttpRequest = tabState.requests.some((r) => {
        return r.domain === u.hostname && r.url.startsWith("http://");
      });
      if (!hadHttpRequest) {
        tabState.supercookieSignals.hstsHeuristic = true;
      }
    }
  }

  browser.webRequest.onBeforeRequest.addListener(
    async (details) => {
      if (details.tabId < 0) return;
      await updateTabUrl(details.tabId);
      const s = ensureTabState(details.tabId);

      const reqUrl = safeUrl(details.url);
      if (!reqUrl) return;

      const rec = {
        url: details.url,
        domain: reqUrl.hostname,
        type: details.type,
        thirdParty: isThirdParty(s.tabUrl, details.url),
        time: Date.now()
      };
      s.requests.push(rec);

      if (rec.thirdParty) {
        s.thirdPartyDomains.add(rec.domain);
      }

      if (details.type === "script" && classifyScriptSuspicious(s.tabUrl, details.url)) {
        s.suspiciousScripts.push({ url: details.url, domain: rec.domain, time: Date.now() });
      }

      trackHstsHeuristic(s, details);
    },
    { urls: ["<all_urls>"] }
  );

  browser.webRequest.onHeadersReceived.addListener(
    async (details) => {
      if (details.tabId < 0) return;
      const s = ensureTabState(details.tabId);
      const headers = details.responseHeaders || [];
      const etag = headers.find((h) => h.name && h.name.toLowerCase() === "etag");
      if (!etag || !etag.value) return;

      const domain = safeUrl(details.url)?.hostname;
      if (!domain) return;

      const existing = s.responseEtags.get(domain) || new Set();
      existing.add(etag.value);
      s.responseEtags.set(domain, existing);

      if (existing.size >= 2 && isThirdParty(s.tabUrl, details.url)) {
        if (!s.supercookieSignals.etagTrackingCandidates.includes(domain)) {
          s.supercookieSignals.etagTrackingCandidates.push(domain);
        }
      }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
  );

  browser.runtime.onMessage.addListener(async (msg, sender) => {
    const tabId = sender.tab?.id ?? msg.tabId;

    if (msg?.type === "PM_STORAGE_SUMMARY" && tabId >= 0) {
      const s = ensureTabState(tabId);
      s.storageSummary = msg.payload;
      return { ok: true };
    }

    if (msg?.type === "PM_FINGERPRINT_EVENT" && tabId >= 0) {
      const s = ensureTabState(tabId);
      s.fingerprintingEvents.push(msg.payload);
      return { ok: true };
    }

    if (msg?.type === "PM_REDIRECT_EVENT" && tabId >= 0) {
      const s = ensureTabState(tabId);
      s.redirectEvents.push(msg.payload);
      return { ok: true };
    }

    if (msg?.type === "PM_GET_SNAPSHOT") {
      const targetTabId = msg.tabId;
      if (typeof targetTabId !== "number") return { ok: false, error: "tabId ausente" };

      await refreshCookies(targetTabId);
      const snapshot = await buildSnapshot(targetTabId);
      await browser.storage.local.set({ [`snapshot_${targetTabId}`]: snapshot });
      return { ok: true, snapshot };
    }

    return undefined;
  });

  browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "loading") {
      stateByTab.set(tabId, {
        tabId,
        tabUrl: tab.url || "",
        firstPartyDomain: safeUrl(tab.url || "")?.hostname || "",
        requests: [],
        thirdPartyDomains: new Set(),
        suspiciousScripts: [],
        redirectEvents: [],
        storageSummary: {
          localStorage: { keys: [], estimatedBytes: 0 },
          sessionStorage: { keys: [], estimatedBytes: 0 },
          indexedDB: { databases: [], estimatedBytes: 0, inaccessible: false }
        },
        cookiesSummary: {
          all: [],
          firstParty: [],
          thirdParty: [],
          session: [],
          persistent: []
        },
        supercookieSignals: { hstsHeuristic: false, etagTrackingCandidates: [] },
        fingerprintingEvents: [],
        responseEtags: new Map()
      });
    }
  });

  browser.tabs.onRemoved.addListener((tabId) => {
    stateByTab.delete(tabId);
  });
})();

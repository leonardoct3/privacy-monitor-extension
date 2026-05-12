(function () {
  const byteLen = (s) => new TextEncoder().encode(String(s)).length;

  function send(type, payload) {
    browser.runtime.sendMessage({ type, payload }).catch(() => {});
  }

  function collectStorageSummary() {
    const localKeys = [];
    const sessionKeys = [];
    let localBytes = 0;
    let sessionBytes = 0;

    try {
      for (let i = 0; i < localStorage.length; i += 1) {
        const k = localStorage.key(i);
        if (k == null) continue;
        const v = localStorage.getItem(k) || "";
        localKeys.push(k);
        localBytes += byteLen(k) + byteLen(v);
      }
    } catch (_err) {
      // Ignore restricted frames.
    }

    try {
      for (let i = 0; i < sessionStorage.length; i += 1) {
        const k = sessionStorage.key(i);
        if (k == null) continue;
        const v = sessionStorage.getItem(k) || "";
        sessionKeys.push(k);
        sessionBytes += byteLen(k) + byteLen(v);
      }
    } catch (_err) {
      // Ignore restricted frames.
    }

    return {
      localStorage: { keys: localKeys, estimatedBytes: localBytes },
      sessionStorage: { keys: sessionKeys, estimatedBytes: sessionBytes }
    };
  }

  async function collectIndexedDBSummary() {
    const data = {
      databases: [],
      estimatedBytes: 0,
      inaccessible: false
    };

    try {
      if (!indexedDB.databases) {
        data.inaccessible = true;
        return data;
      }

      const dbs = await indexedDB.databases();
      for (const dbInfo of dbs) {
        const name = dbInfo.name || "(sem_nome)";
        const version = dbInfo.version || null;
        data.databases.push({ name, version, objectStores: [] });

        // Heuristica de tamanho: usar JSON de metadados de DB.
        data.estimatedBytes += byteLen(name) + byteLen(version || "");
      }
    } catch (_err) {
      data.inaccessible = true;
    }

    return data;
  }

  async function reportStorage() {
    const base = collectStorageSummary();
    const idb = await collectIndexedDBSummary();

    send("PM_STORAGE_SUMMARY", {
      localStorage: base.localStorage,
      sessionStorage: base.sessionStorage,
      indexedDB: idb
    });
  }

  function injectPageHooks() {
    const script = document.createElement("script");
    script.textContent = `
      (() => {
        const PM_SOURCE = 'privacy-monitor-page';
        const post = (payload) => window.postMessage({ source: PM_SOURCE, payload }, '*');

        const wrap = (obj, methodName, apiLabel) => {
          if (!obj || !obj[methodName] || obj[methodName].__pm_wrapped) return;
          const original = obj[methodName];
          const wrapped = function (...args) {
            post({ type: 'PM_FINGERPRINT_EVENT', data: { api: apiLabel, timestamp: Date.now() } });
            return original.apply(this, args);
          };
          wrapped.__pm_wrapped = true;
          obj[methodName] = wrapped;
        };

        wrap(HTMLCanvasElement && HTMLCanvasElement.prototype, 'toDataURL', 'canvas.toDataURL');
        wrap(CanvasRenderingContext2D && CanvasRenderingContext2D.prototype, 'getImageData', 'canvas.getImageData');
        wrap(WebGLRenderingContext && WebGLRenderingContext.prototype, 'getParameter', 'webgl.getParameter');

        try {
          const originalGetExtension = WebGLRenderingContext.prototype.getExtension;
          if (originalGetExtension && !originalGetExtension.__pm_wrapped) {
            const wrappedGetExt = function (name) {
              if (name === 'WEBGL_debug_renderer_info') {
                post({ type: 'PM_FINGERPRINT_EVENT', data: { api: 'webgl.WEBGL_debug_renderer_info', timestamp: Date.now() } });
              }
              return originalGetExtension.apply(this, arguments);
            };
            wrappedGetExt.__pm_wrapped = true;
            WebGLRenderingContext.prototype.getExtension = wrappedGetExt;
          }
        } catch (_err) {}

        if (window.AudioContext && window.AudioContext.prototype) {
          wrap(window.AudioContext.prototype, 'createOscillator', 'audio.createOscillator');
          wrap(window.AudioContext.prototype, 'createDynamicsCompressor', 'audio.createDynamicsCompressor');
        }
        if (window.webkitAudioContext && window.webkitAudioContext.prototype) {
          wrap(window.webkitAudioContext.prototype, 'createOscillator', 'audio.createOscillator');
          wrap(window.webkitAudioContext.prototype, 'createDynamicsCompressor', 'audio.createDynamicsCompressor');
        }

        const wrapRedirect = (obj, methodName) => {
          if (!obj || !obj[methodName] || obj[methodName].__pm_wrapped) return;
          const original = obj[methodName];
          const wrapped = function (...args) {
            post({
              type: 'PM_REDIRECT_EVENT',
              data: {
                method: methodName,
                target: String(args[0] || ''),
                timestamp: Date.now(),
                suspicious: true
              }
            });
            return original.apply(this, args);
          };
          wrapped.__pm_wrapped = true;
          obj[methodName] = wrapped;
        };

        wrapRedirect(window.location, 'assign');
        wrapRedirect(window.location, 'replace');

        try {
          const desc = Object.getOwnPropertyDescriptor(Location.prototype, 'href');
          if (desc && desc.set && !desc.set.__pm_wrapped) {
            const originalSet = desc.set;
            const wrappedSet = function (value) {
              post({
                type: 'PM_REDIRECT_EVENT',
                data: {
                  method: 'href_setter',
                  target: String(value || ''),
                  timestamp: Date.now(),
                  suspicious: true
                }
              });
              return originalSet.call(this, value);
            };
            wrappedSet.__pm_wrapped = true;
            Object.defineProperty(Location.prototype, 'href', { ...desc, set: wrappedSet });
          }
        } catch (_err) {}
      })();
    `;

    (document.documentElement || document.head || document.body).appendChild(script);
    script.remove();
  }

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    if (!event.data || event.data.source !== "privacy-monitor-page") return;

    const payload = event.data.payload;
    if (!payload || !payload.type) return;

    if (payload.type === "PM_FINGERPRINT_EVENT") {
      send("PM_FINGERPRINT_EVENT", payload.data);
    }

    if (payload.type === "PM_REDIRECT_EVENT") {
      send("PM_REDIRECT_EVENT", payload.data);
    }
  });

  injectPageHooks();
  reportStorage();
  window.addEventListener("load", reportStorage, { once: true });
  setTimeout(reportStorage, 4000);
})();

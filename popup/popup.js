async function getActiveTabId() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0]?.id;
}

function text(el, value) {
  el.textContent = value;
}

function clearAndAppendList(el, items) {
  el.innerHTML = "";
  if (!items.length) {
    const li = document.createElement("li");
    li.textContent = "Nenhum evento detectado.";
    el.appendChild(li);
    return;
  }
  for (const item of items) {
    const li = document.createElement("li");
    li.textContent = item;
    el.appendChild(li);
  }
}

function scoreClass(score) {
  if (score < 50) return "bad";
  if (score < 80) return "warn";
  return "ok";
}

function render(snapshot) {
  const scoreEl = document.getElementById("score");
  const bandEl = document.getElementById("band");
  const score = snapshot.privacyScore.value;

  scoreEl.className = `score ${scoreClass(score)}`;
  text(scoreEl, `Score: ${score}/100`);
  text(bandEl, snapshot.privacyScore.band);

  const thirdPartyItems = snapshot.thirdPartyConnections.map((c) => {
    return `${c.domain} | tipos: ${c.resourceTypes.join(", ")} | reqs: ${c.count}`;
  });
  clearAndAppendList(document.getElementById("thirdPartyList"), thirdPartyItems);

  text(document.getElementById("suspiciousCount"), String(snapshot.suspiciousScripts.length));
  text(document.getElementById("redirectCount"), String(snapshot.redirectEvents.length));

  const st = snapshot.storageSummary;
  const storageText = [
    `localStorage: ${st.localStorage.keys.length} chaves, ~${st.localStorage.estimatedBytes} bytes`,
    `sessionStorage: ${st.sessionStorage.keys.length} chaves, ~${st.sessionStorage.estimatedBytes} bytes`,
    `IndexedDB: ${st.indexedDB.databases.length} DBs, ~${st.indexedDB.estimatedBytes} bytes${
      st.indexedDB.inaccessible ? " (acesso limitado)" : ""
    }`
  ].join(" | ");
  text(document.getElementById("storageSummary"), storageText);

  const ck = snapshot.cookiesSummary;
  const cookiesText = [
    `Total: ${ck.all.length}`,
    `1a parte: ${ck.firstParty.length}`,
    `3a parte: ${ck.thirdParty.length}`,
    `Sessao: ${ck.session.length}`,
    `Persistentes: ${ck.persistent.length}`
  ].join(" | ");
  text(document.getElementById("cookiesSummary"), cookiesText);

  const sc = snapshot.supercookieSignals;
  text(
    document.getElementById("supercookies"),
    `HSTS heuristica: ${sc.hstsHeuristic ? "sim" : "nao"} | ETag candidatos: ${sc.etagTrackingCandidates.length}`
  );

  const fpCounts = {};
  for (const ev of snapshot.fingerprintingEvents) {
    fpCounts[ev.api] = (fpCounts[ev.api] || 0) + 1;
  }
  const fpItems = Object.entries(fpCounts).map(([api, count]) => `${api}: ${count}`);
  clearAndAppendList(document.getElementById("fpList"), fpItems);

  const breakdownItems = snapshot.privacyScore.breakdown.map((b) => `${b.label}: ${b.value}`);
  clearAndAppendList(document.getElementById("scoreBreakdown"), breakdownItems);
}

async function init() {
  const tabId = await getActiveTabId();
  if (typeof tabId !== "number") {
    document.getElementById("score").textContent = "Nao foi possivel identificar a aba ativa.";
    return;
  }

  const resp = await browser.runtime.sendMessage({ type: "PM_GET_SNAPSHOT", tabId });
  if (!resp?.ok) {
    document.getElementById("score").textContent = "Falha ao obter dados de privacidade.";
    return;
  }
  render(resp.snapshot);
}

init().catch(() => {
  document.getElementById("score").textContent = "Erro ao carregar popup.";
});

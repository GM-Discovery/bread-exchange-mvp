
(function () {
  try {
    let n = 0;
    document.addEventListener("click", (e) => {
      n++;
      const t = e.target && e.target.id ? `#${e.target.id}` : (e.target && e.target.tagName ? e.target.tagName : "unknown");
      console.log("UI_CLICK", n, t);

      // Update / create a badge
      let b = document.getElementById("uiClickMarker");
      if (!b) {
        b = document.createElement("div");
        b.id = "uiClickMarker";
        b.style.cssText = "position:fixed;bottom:8px;right:8px;z-index:999999;background:#111;color:#fff;padding:6px 10px;border-radius:8px;font:12px/1.2 system-ui;opacity:.9";
        document.addEventListener("DOMContentLoaded", () => document.body.appendChild(b));
        if (document.body) document.body.appendChild(b);
      }
      b.textContent = `Clicks seen: ${n} (${t})`;
    }, true); // capture phase: sees clicks even if something stops bubbling
  } catch (_) {}
})();
(function () {
  try {
    const d = document.createElement("div");
    d.id = "uiBootMarker";
    d.textContent = "UI JS loaded ✅";
    d.style.cssText = "position:fixed;bottom:8px;left:8px;z-index:999999;background:#111;color:#fff;padding:6px 10px;border-radius:8px;font:12px/1.2 system-ui;opacity:.9";
    document.addEventListener("DOMContentLoaded", () => document.body.appendChild(d));
  } catch (_) {}
})();
window.addEventListener("error", (e) => {
  try {
    const d = document.createElement("div");
    d.textContent = "UI ERROR: " + (e && e.message ? e.message : "unknown");
    d.style.cssText = "position:fixed;bottom:44px;left:8px;z-index:999999;background:#8b0000;color:#fff;padding:6px 10px;border-radius:8px;font:12px/1.2 system-ui;opacity:.95";
    document.body.appendChild(d);
  } catch (_) {}
});
window.addEventListener("unhandledrejection", (e) => {
  try {
    const d = document.createElement("div");
    d.textContent = "UI REJECTION: " + (e && e.reason ? String(e.reason) : "unknown");
    d.style.cssText = "position:fixed;bottom:80px;left:8px;z-index:999999;background:#8b0000;color:#fff;padding:6px 10px;border-radius:8px;font:12px/1.2 system-ui;opacity:.95";
    document.body.appendChild(d);
  } catch (_) {}
});
// pisentry site: theme switch, nav, tabs, copy buttons, hero alerts, roadmap filters.
// No dependencies. Every page works without this file; it only adds interaction.
(function () {
  "use strict";
  var root = document.documentElement;

  // Theme: Auto follows the system, Light and Dark are saved per browser.
  var themeButtons = document.querySelectorAll("[data-theme-set]");
  function currentTheme() { return root.getAttribute("data-theme") || "auto"; }
  function paintThemeButtons() {
    var t = currentTheme();
    themeButtons.forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.themeSet === t)); });
  }
  themeButtons.forEach(function (b) {
    b.addEventListener("click", function () {
      var t = b.dataset.themeSet;
      if (t === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", t);
      try { if (t === "auto") localStorage.removeItem("pisentry-theme"); else localStorage.setItem("pisentry-theme", t); } catch (e) { /* ignore */ }
      paintThemeButtons();
    });
  });
  paintThemeButtons();

  // Mobile nav.
  var toggle = document.querySelector(".nav-toggle");
  var links = document.getElementById("nav-links");
  if (toggle && links) {
    toggle.addEventListener("click", function () {
      var open = links.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
    links.addEventListener("click", function (e) {
      if (e.target.closest("a")) { links.classList.remove("open"); toggle.setAttribute("aria-expanded", "false"); }
    });
  }

  // Tabs with arrow-key support.
  document.querySelectorAll("[data-tabs]").forEach(function (box) {
    var tabs = Array.prototype.slice.call(box.querySelectorAll('[role="tab"]'));
    function select(tab, focus) {
      tabs.forEach(function (t) {
        var on = t === tab;
        t.setAttribute("aria-selected", String(on));
        t.tabIndex = on ? 0 : -1;
        var panel = document.getElementById(t.getAttribute("aria-controls"));
        if (panel) panel.hidden = !on;
      });
      if (focus) tab.focus();
    }
    tabs.forEach(function (t, i) {
      t.addEventListener("click", function () { select(t, false); });
      t.addEventListener("keydown", function (e) {
        var j = null;
        if (e.key === "ArrowRight") j = (i + 1) % tabs.length;
        if (e.key === "ArrowLeft") j = (i - 1 + tabs.length) % tabs.length;
        if (e.key === "Home") j = 0;
        if (e.key === "End") j = tabs.length - 1;
        if (j !== null) { e.preventDefault(); select(tabs[j], true); }
      });
    });
    var first = tabs.filter(function (t) { return t.getAttribute("aria-selected") === "true"; })[0] || tabs[0];
    if (first) select(first, false);
  });

  // Copy buttons copy the <pre> next to them.
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var pre = btn.parentElement.querySelector("pre");
      if (!pre || !navigator.clipboard) return;
      navigator.clipboard.writeText(pre.textContent).then(function () {
        btn.textContent = "Copied";
        btn.classList.add("done");
        setTimeout(function () { btn.textContent = "Copy"; btn.classList.remove("done"); }, 1600);
      });
    });
  });

  // Hero: cycle through sample alerts. Message formats match the detectors.
  var toast = document.getElementById("toast");
  var still = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (toast && !still) {
    var events = [
      ["critical", "PS08", "Reverse shell", "Reverse shell: bash (pid 5358) has fd 0 connected to 192.0.2.2:4445"],
      ["high", "PS01", "SSH brute force", "SSH brute force from 203.0.113.50: 9 failed attempts in 5m"],
      ["critical", "PS06", "Cryptominer", "Possible cryptominer xmrig (pid 7121): known miner name: xmrig"],
      ["critical", "PS02", "Suspicious login", "SSH login as pi from 198.51.100.23 (password): after 6 failed attempts from the same source"],
      ["critical", "PS07", "Unexpected listener", "New tcp listener on 0.0.0.0:4444 (nc), not in baseline"],
      ["medium", "PS03", "Insecure posture", "Posture check SSH-01 failing: SSH password authentication enabled"]
    ];
    var slot = {};
    toast.querySelectorAll("[data-t]").forEach(function (el) { slot[el.dataset.t] = el; });
    var i = 0;
    setInterval(function () {
      toast.classList.add("is-out");
      setTimeout(function () {
        i = (i + 1) % events.length;
        var ev = events[i];
        slot.sev.textContent = ev[0];
        slot.sev.className = "sev sev-" + ev[0];
        slot.id.textContent = ev[1];
        slot.name.textContent = ev[2];
        slot.msg.textContent = ev[3];
        toast.classList.remove("is-out");
      }, 380);
    }, 4200);
  }

  // Roadmap filters: area and priority chips, plus a closed toggle.
  var filterBox = document.querySelector("[data-filters]");
  if (filterBox) {
    filterBox.hidden = false;
    var state = { area: "all", prio: "all", closed: true };
    var issues = document.querySelectorAll("[data-issue]");
    var cards = document.querySelectorAll("[data-milestone]");
    function apply() {
      issues.forEach(function (li) {
        var areas = (li.dataset.area || "").split(" ");
        var ok = (state.area === "all" || areas.indexOf(state.area) !== -1) &&
                 (state.prio === "all" || li.dataset.prio === state.prio) &&
                 (state.closed || li.dataset.state !== "closed");
        li.hidden = !ok;
      });
      cards.forEach(function (card) {
        var any = card.querySelector("[data-issue]:not([hidden])");
        var filtering = state.area !== "all" || state.prio !== "all";
        card.hidden = filtering && !any;
      });
    }
    filterBox.querySelectorAll("[data-f]").forEach(function (b) {
      b.addEventListener("click", function () {
        var key = b.dataset.f;
        if (key === "closed") {
          state.closed = !state.closed;
          b.setAttribute("aria-pressed", String(!state.closed));
        } else {
          state[key] = b.dataset.v;
          filterBox.querySelectorAll('[data-f="' + key + '"]').forEach(function (o) {
            o.setAttribute("aria-pressed", String(o === b));
          });
        }
        apply();
      });
    });
  }
})();

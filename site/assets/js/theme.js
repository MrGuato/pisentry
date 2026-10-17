// Runs in <head> before first paint so a saved theme never flashes.
(function () {
  try {
    var t = localStorage.getItem("pisentry-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
  } catch (e) { /* storage blocked: follow the system theme */ }
})();

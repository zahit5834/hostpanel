// HostPanel client glue. No inline scripts anywhere (strict CSP); Alpine runs
// in its CSP build, so components are registered here by name.
(function () {
  "use strict";

  // Theme: explicit choice stored per browser; default follows the OS.
  try {
    var saved = localStorage.getItem("hp-theme");
    if (saved) document.documentElement.setAttribute("data-theme", saved);
  } catch (e) {}

  // Send the CSRF token with every HTMX request.
  document.addEventListener("htmx:configRequest", function (ev) {
    var m = document.querySelector('meta[name="csrf-token"]');
    if (m && m.content) ev.detail.headers["X-CSRF-Token"] = m.content;
  });

  // Show server error text for failed HTMX requests instead of failing silently.
  document.addEventListener("htmx:responseError", function (ev) {
    var xhr = ev.detail.xhr;
    if (xhr.status === 401) return;
    alert((xhr.responseText || "İstek başarısız") + " (" + xhr.status + ")");
  });

  // Keep the job console scrolled to the bottom unless the user scrolled up.
  document.addEventListener("htmx:sseBeforeMessage", function () {
    var c = document.getElementById("console");
    if (c) c.dataset.stick = (c.scrollHeight - c.scrollTop - c.clientHeight < 40) ? "1" : "0";
  });
  document.addEventListener("htmx:sseMessage", function () {
    var c = document.getElementById("console");
    if (c && c.dataset.stick !== "0") c.scrollTop = c.scrollHeight;
  });

  document.addEventListener("alpine:init", function () {
    window.Alpine.data("theme", function () {
      return {
        toggle: function () {
          var root = document.documentElement;
          var cur = root.getAttribute("data-theme");
          if (!cur) cur = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
          var next = cur === "dark" ? "light" : "dark";
          root.setAttribute("data-theme", next);
          try { localStorage.setItem("hp-theme", next); } catch (e) {}
        }
      };
    });

    window.Alpine.data("nav", function () {
      return {
        open: false,
        toggle: function () { this.open = !this.open; },
        get openClass() { return this.open ? "open" : ""; }
      };
    });

    window.Alpine.data("copy", function () {
      return {
        label: "Kopyala",
        copy: function () {
          var el = document.getElementById(this.$el.dataset.target);
          var self = this;
          if (!el || !navigator.clipboard) return;
          navigator.clipboard.writeText(el.textContent.trim()).then(function () {
            self.label = "Kopyalandı ✓";
          });
        }
      };
    });
  });
})();

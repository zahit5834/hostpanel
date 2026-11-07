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

  // Plain (non-HTMX) forms: buttons with data-confirm ask first.
  document.addEventListener("submit", function (ev) {
    var b = ev.submitter;
    if (b && b.dataset && b.dataset.confirm && !window.confirm(b.dataset.confirm)) ev.preventDefault();
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

    // Deploy upload: show XHR upload progress (htmx fires htmx:xhr:progress on the form).
    window.Alpine.data("upload", function () {
      return {
        active: false, pct: 0, label: "",
        init: function () {
          var self = this;
          this.$el.addEventListener("htmx:xhr:progress", function (e) {
            if (!e.detail.lengthComputable || !e.detail.total) return;
            self.active = true;
            self.pct = Math.round(e.detail.loaded * 100 / e.detail.total);
            self.label = self.pct < 100 ? "Yükleniyor… %" + self.pct : "Yüklendi, deploy başlatılıyor…";
          });
        }
      };
    });

    // Env editor: add/remove key-value rows. x-on passes the event to methods.
    window.Alpine.data("envEditor", function () {
      return {
        add: function () {
          var rows = this.$refs.rows;
          var last = rows.lastElementChild;
          if (!last) return;
          var row = last.cloneNode(true);
          row.querySelectorAll("input").forEach(function (i) { i.value = ""; });
          rows.appendChild(row);
          row.querySelector("input").focus();
        },
        remove: function (ev) {
          var row = ev.target.closest(".env-row");
          var rows = this.$refs.rows;
          if (rows.children.length > 1) { row.remove(); return; }
          row.querySelectorAll("input").forEach(function (i) { i.value = ""; });
        }
      };
    });

    // fileToText: read a small local PEM file into the sibling textarea so the
    // form stays urlencoded (no multipart upload for certificates).
    window.Alpine.data("fileToText", function () {
      return {
        load: function (ev) {
          var f = ev.target.files && ev.target.files[0];
          var ta = this.$refs.text;
          if (!f || !ta) return;
          if (f.size > 65536) { alert("Dosya çok büyük (en fazla 64 KB)"); ev.target.value = ""; return; }
          f.text().then(function (t) { ta.value = t; });
        }
      };
    });

    // DNS record form: show the fields the selected type uses.
    window.Alpine.data("dnsRecord", function () {
      var hints = {
        A: ["185.48.180.32", "IPv4 adresi"],
        AAAA: ["2001:db8::1", "IPv6 adresi"],
        CNAME: ["hedef.ornek.com", "Tam ad; @ = zone kökü. Aynı adda başka kayıt olamaz."],
        MX: ["mail.ornek.com", "Posta sunucusunun tam adı (öncelik: küçük olan önce)"],
        TXT: ["v=spf1 a mx -all", "Tırnaksız yazın; 255 karakterden uzunsa otomatik bölünür"],
        SRV: ["sip.ornek.com", "Hedef sunucunun tam adı; ad _servis._tcp biçiminde olmalı"],
        CAA: ["letsencrypt.org", "Sertifika vermesine izin verilen CA (issue) veya iodef adresi"],
        NS: ["ns1.baska.com", "Alt alan adını başka nameserver'a devretmek için (kökte değil)"]
      };
      return {
        type: "A",
        init: function () { this.type = this.$el.dataset.type || "A"; },
        get hasPrio() { return this.type === "MX" || this.type === "SRV" || this.type === "CAA"; },
        get isSRV() { return this.type === "SRV"; },
        get isCAA() { return this.type === "CAA"; },
        get placeholder() { return (hints[this.type] || ["", ""])[0]; },
        get hint() { return (hints[this.type] || ["", ""])[1]; }
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

// Live log consoles ([data-follow]) stay scrolled to the bottom while the
// user is already at the bottom.
document.addEventListener("htmx:sseMessage", function (ev) {
  var c = document.querySelector("[data-follow]");
  if (!c) return;
  if (c.scrollHeight - c.scrollTop - c.clientHeight < 80) c.scrollTop = c.scrollHeight;
});

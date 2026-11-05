{{/* Shared blocks for every site template. Rendered by the panel (Go
     text/template), validated by sites.ValidateConf and again by the root
     helper (validate_nginx_conf) before nginx -t. */}}

{{define "header"}}# Managed by HostPanel ({{.Domain}}) — do not edit: changes are overwritten.
{{- range .RedirectFrom}}
server {
    listen 80;
    listen [::]:80;
{{- if $.Covered .}}{{template "tls" $}}{{end}}
    server_name {{.}};
    access_log {{$.AccessLog}};
    error_log {{$.ErrorLog}};
{{- template "wellknown" $}}
    location / {
        return 301 {{$.RedirectScheme}}://{{$.RedirectTo}}$request_uri;
    }
}
{{- end}}
{{- if and .TLS .ForceHTTPS}}
server {
    listen 80;
    listen [::]:80;
    server_name {{join .ServerNames " "}};
    access_log {{.AccessLog}};
    error_log {{.ErrorLog}};
{{- template "wellknown" .}}
    location / {
        return 301 https://$host$request_uri;
    }
}
{{- end}}
{{end}}

{{define "listen"}}
{{- if not (and .TLS .ForceHTTPS)}}
    listen 80;
    listen [::]:80;
{{- end}}
{{- if .TLS}}{{template "tls" .}}{{end}}
{{- end}}

{{/* Mozilla "intermediate" profile. nginx 1.24 (Ubuntu 24.04) has no
     "http2 on;" directive yet, hence "listen ... ssl http2". */}}
{{define "tls"}}
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    ssl_certificate {{.TLS.Cert}};
    ssl_certificate_key {{.TLS.Key}};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:hp_ssl:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
{{- end}}

{{define "hsts"}}{{if and .TLS .HSTS}}
        add_header Strict-Transport-Security "max-age=31536000" always;{{end}}{{end}}

{{define "wellknown"}}
    location ^~ /.well-known/acme-challenge/ {
        root {{.ACMERoot}};
        default_type text/plain;
    }
{{- if .ProbeToken}}
    location = /.well-known/hostpanel-probe {
        default_type text/plain;
        return 200 "{{.ProbeToken}}";
    }
{{- end}}
{{- end}}

{{define "common"}}
    access_log {{.AccessLog}};
    error_log {{.ErrorLog}};
    client_max_body_size {{.MaxUploadMB}}m;
{{- if and .TLS .HSTS}}
    add_header Strict-Transport-Security "max-age=31536000" always;
{{- end}}
{{- if .Gzip}}
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml image/svg+xml;
{{- end}}
{{template "wellknown" .}}

    error_page 503 /__hostpanel/{{.ErrorPage}};
    location ^~ /__hostpanel/ {
        internal;
        alias {{.PagesDir}};
    }
{{end}}

{{define "nonapp"}}
{{- if eq .Mode "placeholder"}}
    location / {
        root {{.Root}};
        index index.html;
        try_files $uri /index.html;
    }
{{- else}}
    location / {
        # add_header here replaces server-level headers, so HSTS is repeated.
        add_header Retry-After 600 always;{{template "hsts" .}}
        return 503;
    }
{{- end}}
{{end}}

{{define "snippet"}}
{{- if .Snippet}}

    # --- özel snippet ---
{{.Snippet}}
    # --- özel snippet sonu ---
{{- end}}
{{end}}

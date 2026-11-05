{{define "header"}}# Managed by HostPanel ({{.Domain}}) — do not edit: changes are overwritten.
{{- range .RedirectFrom}}
server {
    listen 80;
    listen [::]:80;
    server_name {{.}};
    location ^~ /.well-known/acme-challenge/ {
        root {{$.ACMERoot}};
        default_type text/plain;
    }
    location / {
        return 301 $scheme://{{$.RedirectTo}}$request_uri;
    }
}
{{- end}}
{{end}}

{{define "common"}}
    access_log {{.AccessLog}};
    error_log {{.ErrorLog}};
    client_max_body_size {{.MaxUploadMB}}m;
{{- if .Gzip}}
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml image/svg+xml;
{{- end}}

    location ^~ /.well-known/acme-challenge/ {
        root {{.ACMERoot}};
        default_type text/plain;
    }

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
        add_header Retry-After 600 always;
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

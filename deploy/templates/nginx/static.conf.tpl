{{template "header" .}}
server {
{{- template "listen" .}}
    server_name {{join .ServerNames " "}};
{{template "common" .}}
{{- if eq .Mode "app"}}
    root {{.Root}};
    index {{.Index}};

    location / {
        try_files $uri $uri/ {{if .SPA}}/{{.Index}}{{else}}=404{{end}};
    }

    # Never serve dotfiles (.env, .git, ...).
    location ~ /\.(?!well-known/) {
        deny all;
    }
{{- else}}{{template "nonapp" .}}{{end}}
{{- template "snippet" .}}
}

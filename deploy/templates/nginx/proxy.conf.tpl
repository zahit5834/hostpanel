{{template "header" .}}
server {
    listen 80;
    listen [::]:80;
    server_name {{join .ServerNames " "}};
{{template "common" .}}
{{- if eq .Mode "app"}}
    location / {
        proxy_pass http://127.0.0.1:{{.Port}};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $hp_connection_upgrade;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
{{- else}}{{template "nonapp" .}}{{end}}
{{- template "snippet" .}}
}

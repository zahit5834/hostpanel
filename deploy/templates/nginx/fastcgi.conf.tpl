{{template "header" .}}
server {
{{- template "listen" .}}
    server_name {{join .ServerNames " "}};
{{template "common" .}}
{{- if eq .Mode "app"}}
    root {{.DocRoot}};
    index {{.Index}};

    location / {
        try_files $uri $uri/ {{if .FrontController}}/index.php$is_args$args{{else}}=404{{end}};
    }

    # Never serve dotfiles (.env, .git, ...).
    location ~ /\.(?!well-known/) {
        deny all;
    }
{{- range .NoExecDirs}}

    # Persistent upload directory: files are served, PHP never runs here.
    location ^~ /{{.}}/ {
        location ~ \.(php|phar|phtml)$ { deny all; }
    }
{{- end}}

    location ~ \.php$ {
        try_files $fastcgi_script_name =404;
        fastcgi_split_path_info ^(.+\.php)(/.*)$;
        fastcgi_pass unix:{{.PHPSocket}};
        fastcgi_index index.php;
        fastcgi_read_timeout 300s;
        fastcgi_hide_header X-Powered-By;
        # Parameters are listed inline instead of loading fastcgi_params:
        # site configs may not pull in other files.
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
        fastcgi_param DOCUMENT_ROOT $realpath_root;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_param QUERY_STRING $query_string;
        fastcgi_param REQUEST_METHOD $request_method;
        fastcgi_param CONTENT_TYPE $content_type;
        fastcgi_param CONTENT_LENGTH $content_length;
        fastcgi_param SCRIPT_NAME $fastcgi_script_name;
        fastcgi_param REQUEST_URI $request_uri;
        fastcgi_param DOCUMENT_URI $document_uri;
        fastcgi_param SERVER_PROTOCOL $server_protocol;
        fastcgi_param REQUEST_SCHEME $scheme;
        fastcgi_param HTTPS $https if_not_empty;
        fastcgi_param GATEWAY_INTERFACE CGI/1.1;
        fastcgi_param SERVER_SOFTWARE nginx;
        fastcgi_param REMOTE_ADDR $remote_addr;
        fastcgi_param REMOTE_PORT $remote_port;
        fastcgi_param SERVER_ADDR $server_addr;
        fastcgi_param SERVER_PORT $server_port;
        fastcgi_param SERVER_NAME $server_name;
        fastcgi_param HTTP_PROXY "";
        fastcgi_param REDIRECT_STATUS 200;
    }
{{- else}}{{template "nonapp" .}}{{end}}
{{- template "snippet" .}}
}

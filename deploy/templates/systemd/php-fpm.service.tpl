# Managed by HostPanel — rendered by hp-site-unit.sh; do not edit.
[Unit]
Description=HostPanel PHP site {{domain}}
After=network.target
# Give up restarting after 10 crashes in 2 minutes (shown as "error" in the panel).
StartLimitIntervalSec=120
StartLimitBurst=10

[Service]
Type=notify
User={{user}}
Group={{user}}
WorkingDirectory={{workdir}}
ExecStart={{exec}}
ExecReload=/bin/kill -USR2 $MAINPID
EnvironmentFile={{envfile}}
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=30
SyslogIdentifier={{unit}}

# Resource limits (set per site in the panel).
MemoryMax={{memory}}M
CPUQuota={{cpu}}%
TasksMax=256

# Isolation. (No PrivateDevices: php-fpm logs through /dev/log.)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths={{rwpath}}
UMask=0027

[Install]
WantedBy=multi-user.target

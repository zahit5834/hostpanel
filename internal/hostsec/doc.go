// Package hostsec is the server-security side of the panel (Faz 11): SSH
// login settings and admin keys with a self-reverting apply, the host
// fail2ban jails, the security audit and the integrity check of the
// installed helper scripts. Every change goes through the root helper
// hp-ssh.sh; this package parses its output and validates input first.
package hostsec

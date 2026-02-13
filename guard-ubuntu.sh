#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Ubuntu Security Hardening Script (Root user, SSH key only)
#
# Features:
# - Adds your SSH public key to /root/.ssh/authorized_keys
# - SSH port -> 2218 (ONLY; removes port 22 from sshd configs)
# - PermitRootLogin prohibit-password (root key login allowed)
# - Disables password auth (keys only)
# - UFW firewall: allow 2218/tcp, remove 22/tcp + OpenSSH
# - Fail2Ban configured for SSH on 2218
# - Kernel SYN flood protection (sysctl.d)
# - nftables SSH new-connection rate limit (persistent)
# - CrowdSec + iptables bouncer
#
# Usage:
#   sudo ./harden.sh "ssh-ed25519 AAAA... comment"
#
# IMPORTANT:
# - Keep your current SSH session open.
# - After script finishes, test in a NEW terminal:
#     ssh -p 2222 root@SERVER_IP
# ============================================================

SSH_PUBLIC_KEY="${1:-}"
SSH_PORT="${2:-2222}"

# Optional web ports (set to "no" if not needed)
ALLOW_HTTP="yes"
ALLOW_HTTPS="yes"

log() { echo -e "\n[+] $*\n"; }
die() { echo "ERROR: $*" >&2; exit 1; }

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "Run as root (sudo)."
}

validate_pubkey() {
  [[ -n "${SSH_PUBLIC_KEY}" ]] || die "Usage: sudo ./harden.sh \"ssh-ed25519 AAAA...\""
  if ! echo "${SSH_PUBLIC_KEY}" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+'; then
    die "SSH public key format looks invalid."
  fi
}

install_pubkey_root() {
  log "Installing SSH public key for ROOT user"
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  touch /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys

  if grep -Fq "${SSH_PUBLIC_KEY}" /root/.ssh/authorized_keys; then
    log "Key already exists in /root/.ssh/authorized_keys"
  else
    echo "${SSH_PUBLIC_KEY}" >> /root/.ssh/authorized_keys
    log "Key added to /root/.ssh/authorized_keys"
  fi
}

install_packages() {
  log "Installing required packages (Ubuntu 24.04 safe; no iptables-persistent)"
  apt-get update -y
  apt-get install -y \
    ufw fail2ban curl ca-certificates gnupg lsb-release nftables
}

kernel_hardening() {
  log "Applying kernel SYN-flood + network hardening"
  cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
  sysctl --system
}

enable_ufw_final() {

  log "Enabling UFW firewall"

  ufw --force enable

  systemctl enable ufw
  systemctl restart ufw

  ufw status verbose
}

configure_sshd_force_only_2222() {
  log "Configuring SSH: ONLY port ${SSH_PORT}, keys-only, root key login allowed"
  cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)"

  # Remove any existing Port lines from main config
  sed -i -E '/^\s*#?\s*Port\s+/d' /etc/ssh/sshd_config

  # Also remove any Port directives from included configs to prevent multi-port listening
  if [[ -d /etc/ssh/sshd_config.d ]]; then
    tar -czf "/etc/ssh/sshd_config.d.bak.$(date +%s).tar.gz" /etc/ssh/sshd_config.d 2>/dev/null || true
    find /etc/ssh/sshd_config.d -type f -name "*.conf" -print0 \
      | xargs -0 -r sed -i -E '/^\s*#?\s*Port\s+/d'
  fi

  # Remove conflicting auth/root settings from main config so our appended block is authoritative
  sed -i -E \
    -e '/^\s*#?\s*PasswordAuthentication\s+/d' \
    -e '/^\s*#?\s*KbdInteractiveAuthentication\s+/d' \
    -e '/^\s*#?\s*ChallengeResponseAuthentication\s+/d' \
    -e '/^\s*#?\s*PermitRootLogin\s+/d' \
    -e '/^\s*#?\s*PubkeyAuthentication\s+/d' \
    -e '/^\s*#?\s*UsePAM\s+/d' \
    /etc/ssh/sshd_config

  # Append our hardened settings
  cat >>/etc/ssh/sshd_config <<EOF

# --- Hardening (added by setup script) ---
Port ${SSH_PORT}
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin prohibit-password
UsePAM yes
# ----------------------------------------
EOF

  # Validate config before restarting
  sshd -t
}

restart_ssh_service() {
  log "Restarting SSH service"
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
}

setup_ufw() {
  log "Configuring UFW firewall"
  ufw --force reset

  ufw default deny incoming
  ufw default allow outgoing

  # Allow SSH on 2218
  ufw allow "${SSH_PORT}/tcp" comment "SSH ${SSH_PORT}"

  # Optional web ports
  if [[ "${ALLOW_HTTP}" == "yes" ]]; then ufw allow 80/tcp comment "HTTP"; fi
  if [[ "${ALLOW_HTTPS}" == "yes" ]]; then ufw allow 443/tcp comment "HTTPS"; fi

  # Remove any ssh port 22 allowances if present (safe even if not present)
  ufw delete allow 22/tcp 2>/dev/null || true
  ufw delete allow OpenSSH 2>/dev/null || true

  ufw --force enable
  ufw status verbose || true
}

setup_fail2ban() {
  log "Configuring Fail2Ban for SSH port ${SSH_PORT}"
  cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}
EOF

  systemctl enable fail2ban
  systemctl restart fail2ban
  fail2ban-client status sshd || true
}

setup_nft_rate_limit_ssh() {
  log "Configuring nftables SSH new-connection rate limit (persistent)"
  systemctl enable nftables
  systemctl start nftables

  if [[ -f /etc/nftables.conf ]]; then
    cp /etc/nftables.conf "/etc/nftables.conf.bak.$(date +%s)"
  fi

  # NOTE: This ruleset is intentionally minimal and focused on SSH rate limiting.
  # It does not replace UFW firewall policy; UFW still runs separately.
  # We flush ruleset to ensure predictable behavior.
  cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f

flush ruleset

table inet hardening {
  chain input {
    type filter hook input priority 0; policy accept;

    iif lo accept

    # Allow established/related traffic
    ct state established,related accept

    # Rate-limit NEW SSH connections (mitigate floods/bruteforce bursts)
    tcp dport ${SSH_PORT} ct state new limit rate 30/minute burst 30 packets accept
    tcp dport ${SSH_PORT} ct state new drop
  }
}
EOF

  nft -f /etc/nftables.conf
  systemctl restart nftables
}

install_crowdsec() {
  log "Installing CrowdSec + firewall bouncer (iptables)"
  curl -s https://install.crowdsec.net | bash
  apt-get update -y
  apt-get install -y crowdsec crowdsec-firewall-bouncer-iptables

  systemctl enable crowdsec
  systemctl restart crowdsec
  systemctl enable crowdsec-firewall-bouncer
  systemctl restart crowdsec-firewall-bouncer

  cscli metrics || true
}

verify_listening_ports() {
  log "Verifying sshd listening ports (should be only :${SSH_PORT})"
  ss -tlnp | grep -E 'sshd|:22|:'"${SSH_PORT}" || true
}

final_message() {
  log "Hardening complete"
  echo "✅ SSH port is now: ${SSH_PORT}"
  echo "✅ Password login disabled (SSH keys only)"
  echo "✅ Root login allowed via key only (PermitRootLogin prohibit-password)"
  echo ""
  echo "TEST NOW (in a NEW terminal) before closing this session:"
  echo "  ssh -p ${SSH_PORT} root@<server_ip>"
  echo ""
  echo "Useful checks:"
  echo "  sudo ufw status verbose"
  echo "  sudo fail2ban-client status sshd"
  echo "  sudo cscli metrics && sudo cscli decisions list"
  echo "  sudo nft list ruleset"
  echo "  ss -tlnp | grep sshd"
}

main() {
  require_root
  validate_pubkey

  install_pubkey_root
  install_packages
  kernel_hardening

  configure_sshd_force_only_2222
  restart_ssh_service

  setup_ufw
  setup_fail2ban
  setup_nft_rate_limit_ssh
  install_crowdsec

  verify_listening_ports
  enable_ufw_final  
  final_message
}

main "$@"

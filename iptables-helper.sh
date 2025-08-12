#!/bin/bash
# helper: attach/detach NFQUEUE rules (use sudo)

case "$1" in
  attach)
    iptables-save > ~/iptables-before-fw.rules
    iptables -I INPUT -j NFQUEUE --queue-num 1
    iptables -I FORWARD -j NFQUEUE --queue-num 1
    echo "Attached NFQUEUE rules."
    ;;
  detach)
    if [ -f ~/iptables-before-fw.rules ]; then
      iptables-restore < ~/iptables-before-fw.rules
      echo "Restored previous iptables rules."
    else
      iptables -D INPUT -j NFQUEUE --queue-num 1 2>/dev/null || true
      iptables -D FORWARD -j NFQUEUE --queue-num 1 2>/dev/null || true
      echo "Detached NFQUEUE rules (best-effort)."
    fi
    ;;
  *)
    echo "Usage: $0 {attach|detach}"
    ;;
esac

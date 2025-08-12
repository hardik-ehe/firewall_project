#!/bin/bash

echo "Starting demo..."

# Make sure iptables rules are set
sudo iptables -I INPUT -j NFQUEUE --queue-num 1
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1

# Start firewall in background
sudo python3 firewall.py start &
FW_PID=$!
sleep 3

echo "Adding blocked IP 8.8.8.8"
sudo python3 firewall.py add-ip 8.8.8.8

echo "Pinging 8.8.8.8 (should fail)..."
ping -c 3 8.8.8.8

echo "Removing blocked IP 8.8.8.8"
sudo python3 firewall.py remove-ip 8.8.8.8

echo "Pinging 8.8.8.8 again (should succeed)..."
ping -c 3 8.8.8.8

echo "Blocking port 80 (HTTP)"
sudo python3 firewall.py add-port 80

echo "Trying curl http://example.com (should fail)..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://example.com) || true
if [ "$HTTP_STATUS" != "200" ]; then
  echo "Curl failed as expected (HTTP status: $HTTP_STATUS)"
else
  echo "Unexpected success (HTTP status: $HTTP_STATUS)"
fi

echo "Removing port 80 block"
sudo python3 firewall.py remove-port 80

echo "Trying curl http://example.com again (should succeed)..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://example.com) || true
if [ "$HTTP_STATUS" = "200" ]; then
  echo "Curl succeeded (HTTP status: $HTTP_STATUS)"
else
  echo "Curl failed (HTTP status: $HTTP_STATUS)"
fi

echo "Stopping firewall..."
sudo kill $FW_PID

# Flush iptables rules for cleanup
sudo iptables -F

echo "Demo complete."

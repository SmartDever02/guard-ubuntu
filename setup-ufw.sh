# clear ufw rules
# sudo ufw reset

VALIDATOR_IPS=(
  3.12.58.137
  8.222.159.159
  167.150.153.92
  192.150.253.122
  54.228.70.29
  34.63.115.133
)

sudo ufw default deny incoming
sudo ufw default allow outgoing

# allow validators full access to all ports
for ip in "${VALIDATOR_IPS[@]}"; do
  sudo ufw allow from $ip
done

sudo ufw allow 2218/tcp

sudo ufw enable

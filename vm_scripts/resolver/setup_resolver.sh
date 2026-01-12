
apk add unbound
rc-update add unbound
rc-service unbound start

cat > /etc/unbound/unbound.conf << 'EOF'
server:
    interface: 0.0.0.0
    access-control: 10.0.2.0/24 allow
    access-control: 127.0.0.0/8 allow

    do-ip4: yes
    do-udp: yes
    do-tcp: yes

    hide-identity: yes
    hide-version: yes

    verbosity: 1

forward-zone:
    name: "."
    forward-addr: 8.8.8.8

forward-zone:
    name: "attacker.com."
    forward-addr: 10.0.2.52

EOF

rc-service unbound restart


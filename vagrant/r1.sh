#!/usr/bin/env bash
yum -y install frr
setsebool -P zebra_write_config=1

tee /etc/frr/daemons <<EOF
watchfrr_enable=yes
watchfrr_options="-r '/usr/lib/frr/frr restart %s' -s '/usr/lib/frr/frr start %s' -k '/usr/lib/frr/frr stop %s'"

zebra=yes
bgpd=yes
ospfd=no
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=no
nhrpd=no
eigrpd=no
sharpd=no
pbrd=no
staticd=no
bfdd=no
fabricd=no

zebra_options=("-A 127.0.0.1")
bgpd_options=("-A 127.0.0.1")
ospfd_options=("-A 127.0.0.1")
ospf6d_options=("-A ::1")
ripd_options=("-A 127.0.0.1")
ripngd_options=("-A ::1")
isisd_options=("-A 127.0.0.1")
pimd_options=("-A 127.0.0.1")
nhrpd_options=("-A 127.0.0.1")
eigrpd_options=("-A 127.0.0.1")
sharpd_options=("-A 127.0.0.1")
pbrd_options=("-A 127.0.0.1")
staticd_options=("-A 127.0.0.1")
bfdd_options=("-A 127.0.0.1")
fabricd_options=("-A 127.0.0.1")

vtysh_enable=yes
EOF

tee /etc/frr/bgpd.conf <<EOF
hostname bgpd
password zebra

router bgp 65001
maximum-paths 64
bgp bestpath as-path multipath-relax
bgp router-id 10.20.1.1
network 10.10.1.0/24
network 10.20.1.0/24

timers bgp 2 4

neighbor 10.10.1.2 remote-as 65002
neighbor 10.10.1.2 weight 100
neighbor 10.10.1.2 passive
neighbor 10.10.1.3 remote-as 65002
neighbor 10.10.1.3 weight 100
neighbor 10.10.1.3 passive

log file /var/log/frr/bgpd.log
EOF

sysctl -w net.ipv4.ip_forward=1
chkconfig frr on
service frr restart

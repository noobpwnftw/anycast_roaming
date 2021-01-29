#!/bin/sh
echo "2 anycast" >> /etc/iproute2/rt_tables
tee /sbin/ifup-local <<EOF
#!/bin/sh
ip route add 10.30.1.0/24 dev eth1 src 10.30.1.2 table anycast
ip route add default via 10.30.1.1 dev eth1 table anycast
ip rule add from 10.30.1.0/24 table anycast
ip rule add to 10.30.1.0/24 table anycast
ip rule add oif eth1 lookup anycast
EOF
chmod +x /sbin/ifup-local
/sbin/ifup-local
ping -c 1 10.30.1.1
yum -y install nginx
echo "s2" > /usr/share/nginx/html/index.html
chkconfig nginx on
service nginx start

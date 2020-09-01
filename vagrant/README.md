# Anycast via BGP Routing

## Topology
```
     user
      |
  r2--r1--r3
  |        |
  |        |
  s1      s2
```

BGP Routers: r1-r3
Servers:     s1,s2

Anycast IP: 10.30.1.2

Networks:  

10.30.1.0/24(s1) -> 10.10.1.2(r2) -> 10.20.1.1(r1)  
10.30.1.0/24(s2) -> 10.10.1.3(r3) -> 10.20.1.1(r1)  
10.20.1.0/24(user) -> 10.20.1.11(r1)  

## Tests
    host $ vagrant plugin install vagrant-reload
    host $ vagrant up
    host $ vagrant ssh user
    user $ curl 10.30.1.2
    user $ mtr 10.30.1.2

    host $ vagrant ssh r1
    r1 $ sudo vtysh
    r1 $ clear ip bgp 10.10.1.2
    r1 $ clear ip bgp 10.10.1.3



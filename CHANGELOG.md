## 0.8.0
* Rewrite from Go to Rust
* VPN gateway detection via sysctl, netstat, scutil, and ifconfig fallbacks

## 0.7.2
* allow only UDP for DHCP (removed TCP option since is not used)

## 0.7.0
* Prevent out all IPV6 traffic `block out quick inet6 all`

## 0.6.0
* New option `-local` allows local network traffic, thanks @kabouzeid
* Added the network mask when printing the current IP addresses

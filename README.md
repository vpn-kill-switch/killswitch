# killswitch

VPN kill switch for macOS (Mac OS X >= 10.6), it will block outgoing traffic
when VPN connection fails or crashes.

https://vpn-kill-switch.com/

Usage:

    $ killswitch

To enable:

    $ sudo killswitch -e

To  disable:

    $ sudo killswitch -d

## Compile from source

Setup go environment https://golang.org/doc/install

For example using $HOME/go for your workspace

    $ export GOPATH=$HOME/go

Clone project into that directory:

    $ go get github.com/vpn-kill-switch/killswitch

Build by just typing make:

    $ cd $GOPATH/src/github.com/vpn-kill-switch/killswitch
    $ make

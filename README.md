# killswitch

VPN kill switch for macOS, it will block outgoing traffic when VPN connection
fails or crashes.

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

Create the directory:

    $ mkdir -p $HOME/go/src/github.com/vpn-kill-switch

Clone project into that directory:

    $ git clone git@github.com:vpn-kill-switch/killswitch.git $HOME/go/src/github.com/vpn-kill-switch/killswitch

Build by just typing make:

    $ cd $HOME/go/src/github.com/vpn-kill-switch/killswitch
    $ make

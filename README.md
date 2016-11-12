# killswitch

Command line tool for creating a **kill switch** .pf.conf


Usage:

    $ killswitch -h


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

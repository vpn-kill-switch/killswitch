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


## Activate killswitch at login
Note: I didn't see anyone adding this feature to make the killswitch boot with the mac, therefor I added it here. 
The killswitch was forked from vpn-kill-switch, this is the input I had to this rasp.  


Edit the files "KillSwitch_ON" & "KillSwitch_OFF"

    $ change <User/Sudo_Password> to your user's password

Add KillSwitch_ON to your 'Login Items' so it turns on every time you log in to your user

    $ osascript -e 'tell application "System Events" to make login item at end with properties {path:"/PATH_TO_KILLSWITCH/KillSwitch_ON", hidden:false}'

Remove KillSwitch_ON from your 'Login Items'

    $ osascript -e 'tell application "System Events" to delete login item "KillSwitch_ON"'
    
### Turn off your VPN & log back in without disabling the Kill Switch

For this to work you will need to find a VPN server that you would like to use.
Make sure to favorite that server, for example on NordVPN: United States #3494.

Most VPNS will allow you to use auto-connect feature and pick an exact server.
Tip: Pick the server that gives you the fastest internet connection

Connect to that server through your VPN, and run:

    $ sudo killswitch -e
   
Now your kill switch settings file will have that IP address
   
    $ /tmp/killswitch.pf.conf 
    
Note: The IP will in this file will change when you run "killswitch -e" again
the idea behind this, is that your VPN will always connect to the same IP address.
This way when your VPN disconnects, or crashes, your internet will not work but you can
still connect to your VPN. I find this extremely helpful! 
    
#### Compile from source

Setup go environment https://golang.org/doc/install

For example using $HOME/go for your workspace

    $ export GOPATH=$HOME/go

Clone project into that directory:

    $ go get github.com/vpn-kill-switch/killswitch

Build by just typing make:

    $ cd $GOPATH/src/github.com/vpn-kill-switch/killswitch
    $ make

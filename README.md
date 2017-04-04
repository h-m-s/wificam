# wificam

Research tool based on the following article:
https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html

The article above details several vulnerabilities, the first being the ability to access an .ini file containing the camera's configuration (including the root username/pass) just by supplying a blank username/password. It then uses a RCE flaw in the FTP server to run an instance of netcat pointed back to a configured listener, opening a remote shell for the attacker.

This script acts as a super simple web-server, designed to mimic the servers running on vulnerable cameras. It responds to basic HTTP requests with the exact same responses as an insecure GoAhead camera, and if ran for awhile, should show up on sites like Shodan (https://www.shodan.io/search?query=GoAhead+5ccc069c403ebaf9f0171e9517f40e41) with the exact same HEAD output as one of the GoAhead cameras.

And, when the script given in the link above is ran against the server, it appears to be vulnerable. It returns a configurable username/password to the portion of the script that harvests credentials, and gets the address/port of the attacker's netcat listener from the next payload.

It then uses a Bash script (need to re-write this into the Python script itself eventually) to launch a netcat listener. By default, this connects to localhost at 23, because it's designed to be routed back to the H-M-S telnet honeypot, but you could redirect the traffic where-ever. The H-M-S telnet honeypot has been configured to ignore username/passwords for connections from localhost, and won't give a prompt, making it seem pretty authentic.

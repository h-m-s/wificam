#!/usr/bin/python3
"""
Research tool based on the following article:
https://pierrekim.github.io/blog/2017-03-08-camera-goahead-0day.html

Spins a really dead simple webserver that gives the proper GET and HEAD
responses for a GoAhead camera.

When the script from the article is ran, the server will give a response
with a planted username/pass appearing in the correct spot for the script
to grab it, and think it properly injected the ftp server with
the netcat listener.

This script alone does NOT currently start a netcat instance with the
attacker's server, but does grab the address of the server they're using
and the port they expect to see a netcat connection.

Next step is to implement this by starting a telnet client with a
HoneyTelnetServer with a special username/pass that puts the
HoneyTelnetServer in 'netcat mode', which should be basically
the same exact thing, without a prompt. May have to figure out
if we need to strip out any telnet control characters, etc? But
we can then connect this client directly to the netcat listener,
so for all intents and purposes, it should look exactly like the script
succeeded.

headers are set-up to appear as a GoAhead cam on Shodan:
https://www.shodan.io/search?query=GoAhead+5ccc069c403ebaf9f0171e9517f40e41

"""
import time
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

count = 0
server_address = ('0', 81)

"""
Set the address/port for your server here.
'0' will bind to all addresses. Port should be changed
here, as it will effect the header. Probably doesn't
matter if the header doesn't match the port, but
we're going for authenticity. ;)
"""

class GoAheadHandler(BaseHTTPRequestHandler):
  logfile = "/var/log/hms/wificam-log.txt"
  server_version = "GoAhead-Webs"
  sys_version = ""
  protocol_version="HTTP/1.1"
  """
  Server to mimic a GoAhead camera web server that appears on Shodan
  as a possible vulnerable camera. Returns the proper responses
  to the '0day' script to make attackers think they actually grabbed
  credentials or created a backdoor.
  """
  def date_time_string(self, timestamp=None):
    """
    Let's override the date_time_string function from the base
    so we look identical to a GoAhead cam on Shodan. Nitpicky detail,
    but let's not confuse any bots!
    """
    if timestamp is None:
      timestamp = time.time()
      year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
      s = "%s %3s %0d %02d:%02d:%02d %4d" % (
        self.weekdayname[wd],
        self.monthname[month], day,
        hh, mm, ss, year)
      return s

  def send_error(self, code, message):
    """
    The error messages make it pretty obvious this isn't a GoAhead cam.
    """
    pass

  def log_message(self, format, *args):
    """
    Overwritten for logging straight to a file.
    """
    with open(self.logfile, 'a') as log_file:
      log_file.write("%s - - [%s] %s\n" %
                          (self.client_address[0],
                           self.log_date_time_string(),
                           format%args))
      log_file.write("{}".format(self.headers))
      log_file.flush()

  def do_HEAD(self):
    """
    Just runs do_GET. do_GET checks to see if it's a
    HEAD before sending the body of the response.
    """
    self.do_GET()

  def netcat_honeypot(self, ahost, aport):
    """
    Designed to work with the H-M-S telnet honeypot.
    Basically creates a proxy between the H-M-S telnet
    honeypot and the attacker's netcat listener.

    The telnet honeypot has been modified so that any
    connections coming from the local host
    aren't prompted for a password or sent the prompt.
    More changes might be necessary, but hoping this is enough.

    Right now we're just running the bash script that pops
    open the netcat proxy deal.

    This is a super not-ideal way to do this, but it works
    for the minute. I'd like to at least use Python
    instead of running a bash script, but... the pipes.
    the pipes...
    """

    subprocess.Popen(["./snetcet.sh", ahost, aport])

  def do_POST(self):
    msg = "<html><head><title>Document Error: Unauthorized</title></head>\n"
    msg += "                <body><h2>Access Error: Unauthorized</h2>\n"
    msg += "                <p>Access to this document requires a User ID</p></body></html>\n\n"
    self.send_response(401)
    self.send_header('Except', '100-continue')
    self.send_header('WWW-Authenticate', 'Digest realm="GoAhead", domain=":{}",qop="auth", nonce="a32f2b51bcb55c24d003a21be5ec0345", opaque="5ccc069c403ebaf9f0171e9517f40e41",algorithm="MD5", stale="FALSE"'.format(server_address[1]))
    self.send_header('Pragma', 'no-cache')
    self.send_header('Cache-Control', 'no-cache')
    self.send_header('Content-type','text/html')
    self.end_headers()
    self.wfile.write(bytes(msg, "utf8"))
    self.close_connection = 1

  def do_PUT(self):
    """
    The webcam's default response to random PUTs.
    """
    msg = "<html><head><title>Document Error: Page not found</title></head>\n"
    msg += "                <body><h2>Access Error: Page not found</h2>\n"
    msg +="                <p>Bad request type</p></body></html>\n\n"
    self.send_response(400)
    self.send_header('Pragma', 'no-cache')
    self.send_header('Cache-Control', 'no-cache')
    self.send_header('Content-type','text/html')
    self.end_headers()
    self.wfile.write(bytes(msg, "utf8"))
    self.close_connection = 1

  def do_GET(self):
    """
    Handles all GET requests, including the attacks.
    """
    global count
    msg = "Hello world!"
    if "/system.ini?loginuse&loginpas" in self.requestline:
      """
      This is the line the script uses to snag credentials.
      Currently this just fills in the execess space with 'b's.
      It'd be pretty obvious if you were dumping the output of the script,
      but if you just compile the 0-day script as given and
      run it against this server, it prints to the screen:

      [+] bypassing auth ... done
          login = minad
          pass  = damin
      [+] planting payload ... done
      [+] executing payload ... done
      [+] cleaning payload ... done
      [+] cleaning payload ... done
      [+] enjoy your root shell on REMOTE_HOST:REMOTE_PORT

      It only checks to see that it can harvest the login/pass from the
      step that grabs credentials, and never checks the response from
      the payload itself.
      """
      self.log_message("Attacker attempting to get credentials! Sending fake creds...")
      count = 1
      msg = ("b" * 137) #filler, attack script will skip this to look for uname
      msg += "minad" #username
      msg += ("\0" * 27) # more filler, script skips forward 27 for pass
      msg += "damin" #password
      self.send_response(200)
      self.send_header('Content-type','text/html')
      self.end_headers()
      self.wfile.write(bytes.fromhex('0a0a0a0a01') + bytes(msg, "utf8"))
      self.close_connection = 1
    elif count > 0:
      """
      The first payload the script sends
      contains the login/pass (which should match the ones you provided
      above), but more importantly it contains the server
      and port the attacker should have a netcat listener open on.

      You'd need to connect to this port to make the attacker think they have
      full access.
      """
      for line in self.requestline.split("&"):
        if "loginuse" in line:
          self.log_message("Attacker using login: {}".format(line.split("=")[1]))
        if "loginpas" in line:
          self.log_message("Attacker using password: {}".format(line.split("=")[1]))
        if "pwd" in line:
          temp = line.split("%20")[1].split("+")
          self.log_message("Attacker remote server: {} port: {}".format(temp[0], temp[1]))
          self.netcat_honeypot(temp[0], temp[1])
      count -= 1
    elif self.headers['Authorization'] is not None and "username" in self.headers['Authorization']:
      """
      We'll just direct all username/password logins
      to the 'wrong password' page.

      Something for people who snag the correct username/pass
      would be sweet though...
      """
      msg = "<html><head><title>Document Error: Unauthorized</title></head>\n"
      msg += "        <body><h2>Access Error: Unauthorized</h2>\n"
      msg += "        <p>Access Denied\n"
      msg += "Wrong Password</p></body></html>\n\n"
      self.send_response(401)
      self.send_header('WWW-Authenticate', 'Digest realm="GoAhead", domain=":{}",qop="auth", nonce="a32f2b51bcb55c24d003a21be5ec0345", opaque="5ccc069c403ebaf9f0171e9517f40e41",algorithm="MD5", stale="FALSE"'.format(server_address[1]))
      self.send_header('Pragma', 'no-cache')
      self.send_header('Cache-Control', 'no-cache')
      self.send_header('Content-type','text/html')
      self.end_headers()
      if self.command != "HEAD":
        self.wfile.write(bytes(msg, "utf8"))
      self.close_connection = 1
      self.log_message("Attempted login!")

    else:
      """
      This basically just covers any old GET or HEAD request.
      Fills in the proper headers for a GoAhead camera and the default 401.
      Would be nice to actually have some sort of landing page for the correct
      user/password, because it's going to make the attacker think they obtained
      credentials.

      Perhaps just log every username/pass entered, and set the credentials
      harvested from the script to something unique, so we'd know who
      successfully launched the script, and never have anything past this
      portal.
      """
      msg = "<html><head><title>Document Error: Unauthorized</title></head>\n"
      msg += "                <body><h2>Access Error: Unauthorized</h2>\n"
      msg += "                <p>Access to this document requires a User ID</p></body></html>\n\n"
      self.send_response(401)
      self.send_header('WWW-Authenticate', 'Digest realm="GoAhead", domain=":{}",qop="auth", nonce="a32f2b51bcb55c24d003a21be5ec0345", opaque="5ccc069c403ebaf9f0171e9517f40e41",algorithm="MD5", stale="FALSE"'.format(server_address[1]))
      self.send_header('Pragma', 'no-cache')
      self.send_header('Cache-Control', 'no-cache')
      self.send_header('Content-type','text/html')
      self.end_headers()
      if self.command != "HEAD":
        self.wfile.write(bytes(msg, "utf8"))
      self.close_connection = 1
    return

def run():
  """
  Loop to start the server up, bound to all addresses, on the given port.
  If you change the port, it should change the headers to reflect your new port.
  """
  httpd = HTTPServer(server_address, GoAheadHandler)
  httpd.serve_forever()

run()

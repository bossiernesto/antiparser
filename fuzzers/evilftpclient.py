# evilftpclient.py v1.0
#
# Author: David McKinney
# 
# This is a complex fuzzer example for testing FTP servers.
#
# TODO: Implement more modes
#	Make fuzzer more intelligent
#       Test and tweak

import sys
import getopt
import socket
import string
import getpass
from antiparser import *

def usage():
  help = """Usage: python ap-FTPFuzz.py [options] host
        -c, --command [command]	Fuzz a particular FTP command
     	-d, --debug		Set debugging mode.
        -h, --help		Display this help page.
        -H, --host [host]	Specify a host other than the default of 127.0.0.1.
        -u, --user [user]	Specify FTP user.
        -p, --pass [pass]	Specify FTP pass.
        -P, --port [port]	Specify alternate FTP port (default is 21).
        -s, --sleep [secs]	Number of seconds to sleep between requests.
        --stdin			Prompt for user/pass using stdin
        --fmt			Format string fuzzing mode -- tests FTP commands for format strings.
        --glob			Glob fuzzing mode -- tests FTP commands with malformed globbing strings.
        --save [directory]	Save each permutation to the specified directory.
        NOTE: --save creates a lot of files depending on the fuzzer mode -- one for each payload sent.
  """
  print help

def main(argv):
  # Defaults
  TERMINATOR = "\r\n"
  SEPARATOR = " "
  PORT = 21
  HOST = "127.0.0.1"
  DEBUG = False
  AUTH = False
  USER = ""
  PASS = ""
  CMDFUZZ = False
  MODE = "default"
  SLEEP = False
  TIME = 0
  SAVE = False
  PATH = ""

  # List of commands, including several unsupported verbs (does not include a bunch of SITE subverbs)
  CMDLIST = ['ABOR', 'ALLO', 'APPE', 'CDUP', 'XCUP', 'CWD', 'XCWD', 'DELE', 'HELP', 'LIST', 'MKD',
             'XMKD', 'MACB', 'MODE', 'MTMD', 'NLST', 'NOOP', 'PASS', 'PASV', 'PORT', 'PWD', 'XPWD',
             'QUIT', 'REIN', 'RETR', 'RMD', 'XRMD', 'REST', 'RNFR', 'RNTO', 'SITE', 'SIZE', 'STAT',
             'STOR', 'STRU', 'STOU', 'SYST', 'TYPE', 'USER']

  # Handle arguments
  try:
    opts, args = getopt.getopt(argv, "c:dhH:u:p:P:s:", ["command", "debug", "help", "host=", "user=", 
                                                        "pass=", "port=", "stdin", "fmt", "glob", "sleep=",
                                                        "save="])
  except getopt.GetoptError:
    usage()
    sys.exit(2)
  for opt, arg in opts:
    if opt in ("-h", "--help"):
      usage()
      sys.exit()
    if opt in ("-c", "--command"):
      CMD = arg
    if opt in ("-d", "--debug"):
      DEBUG = True
    if opt in ("-u", "--user"):
      AUTH = True
      USER = arg
    if opt in ("-p", "--pass"):
      AUTH = True
      PASS = arg
    if opt in ("-H", "--host"):
      HOST = arg
    if opt in ("-P", "--port"):
      PORT = int(arg)
    if opt in ("-s", "--sleep"):
      SLEEP = True
      TIME = int(arg)
    if opt in ("--save"):
      SAVE = True
      PATH = arg
    if opt in ("--stdin"):
      AUTH = True
      USER = raw_input('Username: ')
      PASS = getpass.getpass('Password: ')
    if opt in ("--fmt"):
      MODE = "fmt"
    if opt in ("--glob"):
      MODE = "glob"

  table = string.maketrans('', '')
  illegal = string.translate(table, table, string.ascii_letters + string.digits)
    
  # set up antiparser

  for cmd in CMDLIST:
    ap = antiparser()      
    cmdkw = apKeywords()
    if DEBUG:
      cmdkw.setDebug(True)
    cmdkw.setKeywords([cmd])
    cmdkw.setSeparator(SEPARATOR)
    cmdkw.setTerminator(TERMINATOR)

    if MODE == "fmt":
      cmdkw.setContent(r"%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n")
      cmdkw.setOptional(True)
    elif MODE == "glob":
      illegal = string.translate(table, table, "/.{}~*?")
      cmdkw.setIllegalChars(illegal)
    else:
      cmdkw.setIllegalChars(illegal)
    cmdkw.setMode('incremental')
    cmdkw.setMaxSize(65536)
    ap.append(cmdkw)

    if MODE == "default" or MODE == "glob": 
      if MODE == "glob":
        CMDLIST = ['APPE', 'CDUP', 'XCUP', 'CWD', 'XCWD', 'DELE', 'LIST', 'MKD',
                   'XMKD', 'MDTM', 'NLST', 'PWD', 'XPWD', 'RETR', 'RMD', 'XRMD', 
                   'RNFR', 'RNTO', 'STOR', 'STOU']

      for i in xrange(1, 65):
        ap.permute()
        sock = apSocket()
        print "++ Connecting to Server: %s %s" % (HOST, PORT)
        sock.connect(HOST, PORT)
        # print banner
        print sock.recv(10240)
        if AUTH:
          print "++ Sending USER credentials ++"
          sock.sendTCP("USER " + USER + TERMINATOR)
          print sock.recv(10240)
          print "++ Sending PASS credentials ++"
          sock.sendTCP("PASS " + PASS + TERMINATOR)
          print sock.recv(10240)
        
        print "++ Sending command: %s Length: %s ++" % (cmd, cmdkw.getContentSize())
        sock.sendTCP(ap.getPayload())
        print sock.recv(1024)
        sock.close()
        if SAVE:
          file = PATH + "/" + cmd + "fuzz" + str(i)
          print "++ Saving permutation as %s ++" % file
          ap.save(file)
        if SLEEP:
          sock.sleep(TIME)

    if MODE == "fmt":
      sock = apSocket()
      print "++ Connecting to server: %s %s ++" % (HOST, PORT)
      sock.connect(HOST, PORT)
      # print banner
      print sock.recv(1024)
      if AUTH:
        print "++ Sending USER credentials ++"
        sock.sendTCP("USER " + USER + TERMINATOR)
        print sock.recv(1024)
        print "++ Sending PASS credentials ++"
        sock.sendTCP("PASS " + PASS + TERMINATOR)
        print sock.recv(1024)
      print "++ Sending command: %s (Format String Mode) ++" % cmd
      sock.sendTCP(ap.getPayload())
      print sock.recv(1024)
      sock.close()
      if SAVE:
        file = PATH + "/" + cmd + "fuzz" + str(i)
        print "++ Saving permutation as %s ++" % file
        ap.save(file)
      if SLEEP:
        sock.sleep(TIME)

if __name__ == "__main__":
  main(sys.argv[1:])

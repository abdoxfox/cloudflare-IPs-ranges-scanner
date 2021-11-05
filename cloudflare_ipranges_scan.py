
import ipcalc
import socket,random,re


bg=''

G = bg+'\033[32m'
O = bg+'\033[33m'
GR = bg+'\033[37m'
R = bg+'\033[31m'


print(O+'''
\tWEBSOCKET SCANNER
\tBy : ABDOXFOX
'''+GR)

ranges = '''107.154.114.0/24
196.200.152.5/24
104.17.208.0/24
104.17.209.0/24
104.28.21.0/24
104.16.116.0/24
104.24.0.0/14
103.21.244.0/22
172.67.0.0/13
173.245.48.0/20
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
172.64.0.0/13
131.0.72.0/22
172.64.0.0/13
172.65.0.0/13
172.68.0.0/13
172.69.0.0/13
172.70.0.0/13'''
dict={}
print(G+'List of ip ranges :'+GR)
for k,v in enumerate(ranges.split('\n')):
	clr = random.choice([G,GR,O])
	print(f'{clr}{k}-{v}')
	dict[k]=v
print(GR)


choose = input('enter range number : '.title())

def scanner(host):
	sock=socket.socket()
	sock.settimeout(2)
	try:
		sock.connect((str(host),80))
		payload=f'GET / HTTP/1.1\r\nHost: {host}\r\n\r\n'
	
		sock.send(payload.encode())
		response=sock.recv(1024).decode('utf-8','ignore')
		for data in response.split('\r\n'):
			data=data.split(':')
			if re.match(r'HTTP/\d(\.\d)?' ,data[0]):
				print(f'response status : {O}{data[0]}{GR}')
			if data[0]=='Server':
				try:
					if data[1] ==' cloudflare':
						input(f'{G}server : {data[1]}\nFound working ip press any to continue...')
				except Exception as e:
					print(e)
	except Exception as e:print(e)
	
iprange=[]
cidr=dict[int(choose)]	
for ip in ipcalc.Network(cidr):
		iprange.append(ip)
for index in range(len(iprange)):
			try:
				print(f"{R}[INFO] Probing... ({index + 1}/{len(iprange)}) [{iprange[index]}]{GR}")
				scanner(iprange[index])
			except KeyboardInterrupt:
				print(f'{R}Scan aborted by user!{GR}')
				break


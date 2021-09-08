
import ipcalc
import os,platform
import socket,ssl,random
import certifi


bg=''

G = bg+'\033[32m'
O = bg+'\033[33m'
GR = bg+'\033[37m'
R = bg+'\033[31m'


print(O+'''
\tWEBSOCKET SCANNER
\tBy : ABDOXFOX
'''+GR)
port=input('Enter port number : ')
ranges = '''104.28.21.0/24
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
connmethod=int(input('''
Enter your scan method number:
1-with ssl
2-without ssl
: '''))
wshost = input ('Enter websocket host pointed to cloudflare dns : ')
dict={}
print(G+'List of ip ranges :'+GR)
for k,v in enumerate(ranges.split('\n')):
	clr = random.choice([G,GR,O])
	print(f'{clr}{k}-{v}')
	dict[k]=v
print(GR)

choose = input('enter range number : '.title())

def sock(payload,domain,bughost,port):
	dest=f'{bughost}:{port}'
	
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM,)
	s.settimeout(2)
	dest_host=dest.split(':')[0]	
	dest_port=int(dest.split(':')[1])

	try:
		s.connect((dest_host,dest_port))
		if connmethod == 1:
			print(f'{O}SSL handshake with {G}{domain}{GR}	')
			context = ssl.SSLContext(ssl.PROTOCOL_TLS)
			context.verify_mode  = ssl.CERT_REQUIRED
			context.load_verify_locations(

        cafile=os.path.relpath(certifi.where()),

        capath=None,

        cadata=None)
		#	print(context)
			s = context.wrap_socket(s,server_hostname=domain,do_handshake_on_connect=True)
			print(f'{O}Protocol :{G}{s.version()}\n{O}Ciphersuite :{G} {s.cipher()[0]}\n{O}Peerprincipal:{G} C={s.getpeercert()["subject"][0][0][1]} , ST={s.getpeercert()["subject"][1][0][1]} , L={s.getpeercert()["subject"][2][0][1]} , O={s.getpeercert()["subject"][3][0][1]} , CN={s.getpeercert()["subject"][4][0][1]}  {GR}')
		print(f'{R}Payload : {O}{payload}{GR}')
		s.send(payload.encode())
		status = s.recv(1024).decode().split('\n')[0]
		if status[:12] == 'HTTP/1.1 101':
			print(f'{G}response : {status}{GR}')
		else:
			print(f'{R}response : {status}{GR}')
		s.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
		st=s.recv(30).decode('utf-8','ignore')
		if st[:4]=='SSH-':
			print(f'{G}status : {st}{GR}')
			save(payload,bughost)
		else:
			print(f'{R}status : {st}{GR}')
	except Exception as e:
		if str(e)=='_ssl.c:1091: The handshake operation timed out':
			print(R+'CipherSuite: SSL_NULL_WITH_NULL_NULL'+GR)
		else:
			print(R+'Error : '+str(e.args)+GR)
	print('----------------------------------------------')
		
	
	
def paylgen(bughost,domain,port):
		
		payload =f'GET / HTTP/1.1\r\nHost: {domain}\r\nUpgrade: websocket\nConnection: upgrade\r\nProxy-connection: keep-alive\r\n\r\n'
		sock(payload,domain,bughost,port)
def save(payload,bughost):
	file = open('out.txt','a')
	file.write(f'payload :{payload.encode()}\nbughost:{bughost}\n')
	file.write('-------------------------------------------\n')

iprange=[]
cidr=dict[int(choose)]	
for ip in ipcalc.Network(cidr):
		iprange.append(ip)
for index in range(len(iprange)):
			try:
				print(f"{R}[INFO] Probing... ({index + 1}/{len(iprange)}) [{iprange[index]}]{GR}")
				paylgen(iprange[index],wshost,port)
			except KeyboardInterrupt:
				print(f'{R}Scan aborted by user!{GR}')
				break

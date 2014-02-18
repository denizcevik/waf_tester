#Covered by GPL V2.0
#http://www.gnu.org/licenses/gpl-2.0.html
#

import sys
import time
import httplib
import socket
import getopt

# Global Variables
test_db="checklist.txt"
desc_max_len = 110
sleep_time_br = 3
default_timeout=7
default_sleep_time=0	
useragent = "Mozilla/5.0 (X11; U; FreeBSD i386; en-US; rv:1.9.2.9) Gecko/20100913 Firefox/3.6.9"
ssl_port = 443
string = ""
waf_behavior = 0
waf_timeout = 0
print_related = 2 # print ALL. 0 means print Blocked and 1 means print Bypassed
template = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:get="http://www.myserver.com/assets/smp/uum/GetBillingAccounts">
   <soapenv:Header/>
   <soapenv:Body>
           %(key)s
   </soapenv:Body>
</soapenv:Envelope>""" # template SOAP envelope used. Header attacks can be added later on
issoap = 0 # is this a soap request
httpmethod = "GET" # http method used
posturl = "/index.php" # post URL used both in classic form POST and SOAP requests


def check_connection(hostname,port):
	connection = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	try:
		connection.connect((hostname,port))
		return("Success")
	except:
		return("Fail")
	connection.close()

def send_webrequests(hostname,protocol,port,attack_pattern,vvar,n_header):
	if protocol == "http":
		web_connection = httplib.HTTPConnection(hostname,port,timeout=vvar)
	elif protocol == "ssl":
		web_connection = httplib.HTTPSConnection(hostname,port,timeout=vvar)
		        
	if httpmethod == "POST":
                if issoap == 1:                        
                        headers = {'Accept-Encoding': 'gzip,deflate', 'Content-type': 'text/xml;charset=UTF-8', 'SOAPAction': 'GetBillingAccounts', 'User-Agent': useragent, 'Host':'www.myvulnerablewebapplicationserver.com'}
                        web_connection.request("POST", posturl, attack_pattern, headers)
                else:
                        headers = {'Accept-Encoding': 'gzip,deflate', 'Content-type': 'application/x-www-form-urlencoded','User-Agent': useragent,'Host':'www.myvulnerablewebapplicationserver.com'}
                        web_connection.request("POST", posturl, attack_pattern, headers)                        
        else:
                web_connection.putrequest("GET",attack_pattern)
                web_connection.putheader("User-Agent",useragent)                
                web_connection.putheader("Host",'www.myvulnerablewebapplicationserver.com')                
                if n_header != "":
                        h={}
                        (h['header'], h['value'])=n_header.split(":",1)
                        web_connection.putheader(h['header'],h['value'])	
                web_connection.endheaders()
	try:
        	response = web_connection.getresponse()
	except socket.timeout:
		data="blockedbywaforips"
	except socket.error,err:
		error_code=int(err.args[0])
		if error_code == 104:
			data="rejectedbywaforips"
	else:	
		data=str(response.status)+" "+str(response.reason)+" "+str(response.msg)+" "+str(response.read())
	return(data)
	web_connection.close()

def send_packet(hostname,protocol,port,app,w_beh,c_var,st):
	line=0
	bypassed=0
	global issoap
	global httpmethod
	global body
	try:
                attack_data_file=open(test_db)
        except:
                print("[*] Attack database file could not be found.")
                exit()
	print("[+] Sending HTTP requests....")
	for each_attack_pattern in attack_data_file:
                s={}                
		line=line+1
                (s['description'], s['attack_pattern'], s['type'])=each_attack_pattern.split("##")
		attack_description=s['description'].rstrip()
		a_pattern_raw=s['attack_pattern'].rstrip()
		insert_nh=""
		code=int((s['type']).rstrip())
		a_pattern_to_log = ""
		if code == 0:
			a_pattern=(str(s['attack_pattern']).rstrip())
			a_pattern_to_log = a_pattern
		elif code == 1:
			a_pattern=("/"+str(app)+"?id="+str(s['attack_pattern']).rstrip())
			a_pattern_to_log = a_pattern
		elif code == 2:
			a_pattern=("/"+str(app))
			a_pattern_to_log = a_pattern
			insert_nh=s['attack_pattern']
		elif code == 3:
                        httpmethod = "POST"
                        posturl = ("/"+str(app))
                        a_pattern=template % {'key':str(s['attack_pattern']).rstrip()}
                        issoap = 1
                        a_pattern_to_log = str(s['attack_pattern']).rstrip()
                elif code == 4:
                        httpmethod = "POST"                        
                        posturl = ("/"+str(app))
                        a_pattern = "id="+str(s['attack_pattern']).rstrip()
                        a_pattern_to_log = a_pattern
                        
		size=len(attack_description)+len(a_pattern_raw)
		if w_beh == 0:
			response=send_webrequests(hostname,protocol,port,a_pattern,c_var,insert_nh)
			time.sleep(st)
	        	if response != "blockedbywaforips":
				bypassed=bypassed+1
				if print_related == 1 or print_related == 2:
                        		print("  [+] "+attack_description+" "+a_pattern_to_log)
        		else:
                                if print_related == 0 or print_related == 2:
                                        print("  [-] "+attack_description+" "+a_pattern_to_log)
		if w_beh == 1:
			var=default_timeout
			response=send_webrequests(hostname,protocol,port,a_pattern,var,insert_nh)
			time.sleep(st)
			if response.find(c_var) == -1:
				bypassed=bypassed+1
				if print_related == 1 or print_related == 2:
        				print("  [+] "+attack_description+" "+a_pattern_to_log)
			else:
                                if print_related == 0 or print_related == 2:
                                        print("  [-] "+attack_description+" "+a_pattern_to_log)
		if w_beh == 2:
                        var=default_timeout
                        response=send_webrequests(hostname,protocol,port,a_pattern,var,insert_nh)
                        time.sleep(st)
                        if response != "rejectedbywaforips":
				bypassed=bypassed+1
				if print_related == 1 or print_related == 2:
                                        print("  [+] "+attack_description+" "+a_pattern_to_log)
                        else:
                                if print_related == 0 or print_related == 2:
                                        print("  [-] "+attack_description+" "+a_pattern_to_log)
	attack_data_file.close()
	sr=(int(line)-int(bypassed))*100/int(line)
	print("[+] "+str(bypassed)+" of "+str(line)+" attacks could not be detected by WAF/IPS")
	print("[+] Success rate of WAF/IPS : % "+"\033[0;31m%s\033[m" % (str(sr)))
	print("[+] done.")


def parse_url(u):
	convars={}
	hostvars={}
	portnumber=0
	try:
		(convars['proto'], convars['nn'], convars['host'], convars['app'])=u.split("/")
	except:
		print("  [-] Wrong URL...\n")
		exit()
	try:
		(hostvars['hostt'],hostvars['port'])=convars['host'].split(":")
	except:
		if convars['proto'] == "http:":
			portnumber=80
			protocol="http"
			hostname=convars['host']
		elif convars['proto'] == "https:":
			portnumber=443
			protocol="ssl"
			hostname=convars['host']
		else:
			print("  [-] Unrecognized protocol, url must be started with http or https...\n")
                	exit()
	else:
		if convars['proto'] == "http:":
                        portnumber=hostvars['port']
                        protocol="http"
			hostname=hostvars['hostt']
                elif convars['proto'] == "https:":
                        portnumber=hostvars['port']
                        protocol="ssl"
			hostname=hostvars['hostt']
                else:
                        print("  [-] Unrecognized protocol, url must be started with http or https...\n")
                        exit()

	application=convars['app']
	return(hostname,application,int(portnumber),protocol)

def usage():
	print("-----------------------------------------")
	print(" WAF/IPS Tester for Web Attacks v1.0")
	print(" ttlexpired.com ")
	print(" by Deniz CEVIK ")
	print("-----------------------------------------\n")
	print("Usage: waf_tester.py options\n")
	print("Options:\n")
	print("  -u --url: A Single URL behind WAF/IPS")
	print("  -t --type: WAF Behavior (Block/Reset/Response)")
	print("  -w --time-out: timeout value to indetify droped connection")
	print("  -s --string: string value can be found in WAF error code")
	print("  -k --sleep: Wait time before request (default 0 second)")
	print("  -o --output: Print related [Blocked|Bypassed|All] (default All) \n")
	print("Examples:\n")
	print("  python waf_tester.py -u http://www.sitebehindwaf.com/index.asp -t Response --string \"302 Redirect\" --output All")
	print("  python waf_tester.py -u http://www.sitebehinips.com/index.asp -t Block --time-out 10 --output Bypassed")
	print("  python waf_tester.py -u http://www.sitebehindfw.com/index.asp -t Reset --output Blocked")
	print("  python waf_tester.py -u http://www.sitebehindfw.com:8080/index.asp -t Reset\n")
	exit()

sleep_time = default_sleep_time

if len(sys.argv) < 6:
	usage()
else:
	try:
		opts, args = getopt.getopt(sys.argv[1:],"u:t:s:w:k:o",["url=","type=","time-out=","string=","sleep=", "output="])
		argtest=dict(opts)	
	except:
		usage()
	for opt,arg in opts:
		if opt in ("-u","--url"):
			url=str(arg)
		elif opt in ("-o","--output"):
			rel=str(arg)
                        if rel == "Blocked":
                                print_related = 0
                        elif rel == "Bypassed":
                                print_related = 1
		elif opt in ("-t","--type"):
			beh=str(arg)
			if beh == "Block":
				waf_behavior=0
				if "--time-out" in argtest:
					continue
				else:
					print("  [-] Timeout value required for blocking action. use --time-out option.")
					exit()
			elif beh == "Response":
				waf_behavior=1
				if ("--string" or "-s") in argtest:
					continue
				else:
					print(" [-] String value required for WAF Response. use --string option")
                                        exit()	
			elif beh == "Reset":
				waf_behavior=2
			else:
				print("[-] Wrong WAF Behavior. Only Block/Reset/Response available ")
				exit()
		elif opt in ("-w","--time-out"):
			waf_timeout=int(arg)
		elif opt in ("-s","--string"):
			match_string=str(arg)
		elif opt in ("-k","--sleep"):
			sleep_time=int(arg)
		elif opt in ("-p","--ssl-port"):
			ssl_port=int(arg)
		else:
			print("[-] Unhandled option")
			usage()
hostname,application,portnumber,proto=parse_url(url)
if check_connection(hostname,portnumber) == "Success":
	print("[+] Connection established.")
	if waf_behavior == 0:
		print("[+] WAF/IPS action = DROP")
		send_packet(hostname,proto,portnumber,application,waf_behavior,waf_timeout,sleep_time)
	if waf_behavior == 1:
		print("[+] WAF/IPS action = CUSTOM HTTP RESPONSE")                	
		send_packet(hostname,proto,portnumber,application,waf_behavior,match_string,sleep_time)
        if waf_behavior == 2:
		print("[*] WAF/IPS action = TCP RESET")
                send_packet(hostname,proto,portnumber,application,waf_behavior,"null",sleep_time)
	else:
		print("[-] Connection Error") 


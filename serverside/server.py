#!/usr/bin/python
import socket
import threading
import os
import hashlib
import sys
import db
import json
import requests
from time import sleep
#import IPython


important_dirs = ["viruses", "quarantined", "serverfiles"]


myapikey = 'f2a838e95d14f0b506c8391ae8e287ff39461c599a47a2312d75cd580ad5020e'
scan_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
report_url = 'https://www.virustotal.com/vtapi/v2/file/report'

def ProtocolImpl(name, sock):
	funcs = {1 : DownloadFile, 2 : UploadFile, 3 : ListFiles, 4 : Listquarantined, 5 : CloseProgram}
	while True:
		user_choice = sock.recv(1024)
		f = int(user_choice)
		funcs[f](name, sock)

def CloseProgram(name, sock):
	sock.close()
	sys.exit()

def UploadFile(name, sock):
	filename = sock.recv(1024)
	if filename != "ERR":
		sock.send("OK")
		filesize = int(sock.recv(1024))
		sock.send("OK")
		f = open("./quarantined/" + filename, 'wb')
		data = sock.recv(1024)
		totalRecv = len(data)
		f.write(data)
		while (totalRecv < filesize):
			data = sock.recv(1024)
			totalRecv += len(data)
			f.write(data)
			print "{0:.2f}".format((totalRecv/float(filesize)) * 100) + "% Done"
		f.close()
		print "Download Complete!"
		Check_if_virus(filename, sock)

def DownloadFile(name, sock):
	filename = sock.recv(1024)
	path = "./serverfiles/" + filename
	if os.path.isfile(path):
		sock.send("EXISTS" + str(os.path.getsize(path)))
		userResponse = sock.recv(1024)
		if userResponse[:2] == 'OK':
			with open(path, 'rb') as f:
				bytesTosSend = f.read(1024)
				sock.send(bytesTosSend)
				while bytesTosSend != "":
					bytesTosSend = f.read(1024)
					sock.send(bytesTosSend)
	else:
		sock.send("ERR")

def ListFiles(name, sock):
	fileslist = os.listdir("./serverfiles")
	files_in_string = '\n'.join(fileslist)
	if files_in_string != "":
		sock.send(files_in_string)
	else:
		sock.send("No files available")

def Listquarantined(name, sock):
	fileslist = os.listdir("./quarantined")
	files_in_string = '\n'.join(fileslist)
	if files_in_string != "":
		sock.send(files_in_string)
	else:
		sock.send("No quarantined files")

def Check_if_virus(filename, sock):
	cur_path = "./quarantined/" + filename
	dest_path = "./serverfiles/" + filename
	hash_output = MD5_checksum(cur_path)
	print hash_output

	# check if hash exists in DB
	db_result = db.search_in_db(hash_output)

	filesize = os.path.getsize(cur_path)
	if (filesize >> 20) < 32:
		virustotal_ans = check_in_virustotal(filename)
	else:
		print "file weighs 32 MB or more, therefore can't check it with virustotal"
		virustotal_ans = 0

	if len(db_result) == 0 and virustotal_ans['result'] == 0:
		os.rename(cur_path, dest_path)
		sock.send("OK")
		print virustotal_ans['msg']
		print filename + " is clean and moved to serverfiles dir"
	elif not len(db_result) == 0 or virustotal_ans['result'] == 1:
		if not len(db_result) == 0:
			print "Malicious file " + filename + "\nTransfered to quarentine\nVirus name: " + (db_result[0])[1]
		else:
			print virustotal_ans['msg']
		print "Disconnecting user"
		#force disconnection in client
		sock.send("Kill")
		sock.close()
		sys.exit()
	elif virustotal_ans['result'] in [2, 3, 4]:
		print virustotal_ans['msg']
		print "Operation Failed"
		sock.send(virustotal_ans['msg'])
		print "deleting file..."
		os.remove(cur_path)

def MD5_checksum(filename):
	file_hash_md5 = hashlib.md5(file_as_bytes(open(filename, 'rb'))).hexdigest()
	return file_hash_md5

def file_as_bytes(file):
    with file:
        return file.read()

# Analyzing virustotal response
# returning dict
def response_handler(response, report_params):
	if response.status_code == 200:
		print response.json()['verbose_msg']
		num_tries = 1
		while response is not None and 'positives' not in response.json():
			print response.json()['verbose_msg']
			sleep(2)
			if response.json()['verbose_msg'] == "Your resource is queued for analysis".strip():
                                print "wait"
				sleep(15)
			num_tries += 1
			response = requests.get(report_url, params=report_params)
			if not response.status_code == 200:
				print "Server tried " + str(num_tries) + " times"
				return response_handler(response, report_params)
		print "Server tried " + str(num_tries) + " times"

		# print answer_enriched
		if response.json()['positives'] == 0:
			# print "File is clean"
			return dict(result = 0, msg = "File is clean")
		else:
			# print "File is BAD"
			return dict(result = 1, msg = "File is BAD") # "File is BAD"
	elif response.status_code == 204:
		# print "You exceeded the public API request rate limit (4 requests of any nature per minute)"
		return dict(result = 2 , msg = "You exceeded the public API request rate limit (4 requests of any nature per minute)")
	elif response.status_code == 403:
		return dict(result = 3 , msg = "You tried to perform calls to functions for which you require a Private API key.")
	elif response.status_code == 404:
		return dict(result = 4 , msg = "File not found.")

def check_in_virustotal(filename):
	print "in check_in_virustotal"
	cur_path = "./quarantined/" + filename
	# Sending HTML POST request to virustotal with the file to inspect
	scan_params = {'apikey': myapikey}
	files = {'file': (filename, open(cur_path, 'rb'))}
	scan_response = requests.post(scan_url, files=files, params=scan_params)

	# waiting for response from virustotal
	response_in_json = scan_response.json()

	print(response_in_json['verbose_msg'])
	# Sending HTML GET request to virustotal with the file to inspect

	resource = response_in_json['resource']
	report_params = {'apikey': myapikey, 'resource': resource}
	print "waiting for response from virustotal... may take a few seconds"
	answer_response = requests.get(report_url, params=report_params)
	# IPython.embed()
	print answer_response.status_code
	return response_handler(answer_response, report_params)
	
def Main():
	greetings = """               .__                               
__  _  __ ____ |  |   ____  ____   _____   ____  
\ \/ \/ // __ \|  | _/ ___\/  _ \ /     \_/ __ \ 
 \     /\  ___/|  |_\  \__(  <_> )  Y Y  \  ___/ 
  \/\_/  \___  >____/\___  >____/|__|_|  /\___  >
             \/          \/            \/     \/ """
	print greetings
	server_settings = raw_input("Choose 1/2:\n1 -> Default connection settings (loopback:8080)\n2 -> Custumize connection settings\n")
	while not server_settings.isdigit() or int(server_settings) not in [1,2]:
		print "Invalid"
		server_settings = raw_input("Choose 1/2:\n1 -> Default connection settings (loopback:8080)\n2 -> Custumize connection settings\n")
	if int(server_settings) == 2:
		port = int(raw_input("Enter port number ->"))
		host = raw_input("Enter host ip ->")
	else:
		host = '127.0.0.1'
		port = 8080
		

	for dir in important_dirs:
		if not os.path.exists(dir):	
			os.makedirs(dir)
	db.create_db()
	thread = threading.Thread(target=Serve, args=(host, port))
	thread.daemon = True
	thread.start()
	while True:
	    exit_signal = raw_input('Type "exit" anytime to stop server\n')
	    if exit_signal == 'exit':
        	break


def Serve(host, port):
	clientid = 0
	s = socket.socket()
	s.bind((host, port))
	s.listen(5)
	print "Server Started"
	while True:
		c,addr = s.accept()
		clientid += 1
		print "Client connected ip:<" + str(addr) + ">"
		t = threading.Thread(target=ProtocolImpl, args=("Thread" + str(clientid), c))
		t.start()
	
	sock.shutdown(socket.SHUT_RDWR)
	s.close()


if __name__ == '__main__':
	Main()
	os.remove('virus_signatures.db')
	os.remove('server.pyc')
	os.remove('db.pyc')

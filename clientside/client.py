#!/usr/bin/python
import socket
import sys
import os

confirmation_responses = ["y", "yes", "rawn"]

def ProtocolImpl(s):
	menu = """	
What would you like to do?

1. Download file from server
2. Upload file to server
3. Display available files
4. Display quarantined files
5. Quit

"""

	funcs = {1 : DownloadFile, 2 : UploadFile, 3 : ListFiles, 4 : Listquarantined, 5 : CloseProgram}
	while True:
		user_command = raw_input(menu)
		if not user_command.isdigit() or int(user_command) not in funcs:
			print "Invalid"
			continue
		s.send(user_command)
		funcs[int(user_command)](s)

def CloseProgram(s):
	print "Closing Socket"
	s.close()
	sys.exit()

def UploadFile(s):
	filename = raw_input("Filename? -> ")
	if os.path.isfile(filename):
		s.send(filename)
		server_response = s.recv(1024)
		if server_response == "OK":
			s.send(str(os.path.getsize(filename)))
			server_response = s.recv(1024)
			if server_response == "OK":
				with open(filename, 'rb') as f:
					bytesToSend = f.read(1024)
					s.send(bytesToSend)
					while bytesToSend != "":
						bytesToSend = f.read(1024)
						s.send(bytesToSend)
				print "Upload complete!\nServer checking file"
				isfileok = s.recv(1024)
				if isfileok == "Kill":
					print "Operation failed\n" + isfileok
					s.close()
					print "Lost connection to server"
					sys.exit()
				elif isfileok == "OK":
					print "success"
				else:
					print isfileok
	else:
		print filename + " does not exists"
		s.send("ERR")


def ListFiles(s):
	available_files = s.recv(1024)
	print "\nFiles in server:\n" + available_files

def Listquarantined(s):
	quarantined_files = s.recv(1024)
	print quarantined_files

def DownloadFile(s):
	filename = raw_input("Filename? -> ")
	if filename != 'q':
		print "filename is: " + filename
		s.send(filename)
		data = s.recv(1024)
		if data [:6] == 'EXISTS':
			filesize = long(data[6:])
			message = raw_input("File Exists, "+str(filesize)+" Bytes, download? (Y/N)? -> ")
			if message.lower() in confirmation_responses:
				s.send('OK')
				f = open('new_'+filename, 'wb')
				data = s.recv(1024)
				totalRecv = len(data)
				f.write(data)
				while totalRecv < filesize:
					data = s.recv(1024)
					totalRecv += len(data)
					f.write(data)
					print "{0:.2f}".format((totalRecv/float(filesize)) * 100) + "% Done"
				print "Download Complete!\nwaiting for response from server... may take a few seconds"
		else:
			print "File does not Exists"

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

	s = socket.socket()
	
	s.connect((host, port))


	ProtocolImpl(s)


if __name__ == '__main__':
	Main()

#!/usr/bin/env python
# Please compile using Python 3
import socket 		# To manage sockets
import sys 			# To extract command line arguments
import ipaddress 	# To check the validaty of the TCP_IP address entered
import secrets		#  for generating cryptographically strong random numbers
import struct 		# Used to pack and unpack messages in the UDP protocol

'''
generate_keys function
arguments:
	key_size : desired key size to generate
	nbr_of_key: how many keys do you want to generate
return:
	a list of (nbr_of_keys) HEX keys

This function generates HEX random keys using python module 'secrets'
'''
def generate_keys(key_size, nbr_of_keys):
	# Generating the keys that would be used to encryption
	keys = []
	for i in range(nbr_of_keys):
		'''
		secrets.token_hex([nbytes=None])
		Return a random text string, in hexadecimal. The string has nbytes random bytes, 
		each byte converted to two hex digits. If nbytes is None or not supplied, a reasonable default is used.
		'''
		# This would generate n HEX keys of key_size
		keys.append(secrets.token_hex(key_size//2))		# nbytes random bytes => 64 byte

	return keys

'''
embed_key_message
arguments:
	keys: a list of HEX keys
returns:
	a string message that has the form: HELLO ENC -keys-. It does respect the described structure
Since the generate_keys function generate only keys, we need to embed these keys into the message to be sent 
to the server in the format specified on the task sheet
'''
def embed_key_message(keys):
	MESSAGE = "HELLO ENC\r\n"
	for i in range(len(keys)):

		MESSAGE+=(keys[i]+'\r\n')

	# Add the last 'period'
	MESSAGE+=('.\r\n')
	#print(MESSAGE)
	return MESSAGE

'''
extract_server_msg
Arguments:
	data: (binary string) it should be the first binary string received from the server
	features: (list of int) it should contain the features used by the user
return:
	client_id: (string) the client identification token specified by the server
	udp_port: (string) udp port number on  the server
	server_keys: (list) it contains server keys to be used to decryption
Note that extract_server_msg deco, features=0de the binary string received into ordinary ASCII string
Then, it splits the string on (\r\n).
the first element is split on (space) to extract the identification token and upd port number
the last elmenents are discarded ('.') and ('') empty character
'''
def extract_server_msg(data, features=0):
	tmp = data.decode('ascii').split('\r\n')
	[_, client_id, udp_port] = tmp[0].split(' ')		# First element of the server message is Hello identif udp_port
	
	if features == 1: # enc feature was used => let's get the keys
		server_keys = tmp[1:-2]  # Keys are all the vector elements except the first (identif) last (.)
	else:
		server_keys = None
	#print(tmp)
	return client_id, udp_port, server_keys

'''
udp_packet_content_padding function
Arguments:
	udp_packet_content: (string) contains the content of the packet to be sent
return:
	upd_packet_content: (string) of 64 character consists of the initial udp_packet_content and null character padding
udp_packet_content_padding is used in case the content of the udp packet is less than 64 character
in order to pad null character to it
'''
def udp_packet_content_padding(udp_packet_content):
	if len(udp_packet_content) < 64:
		
		udp_packet_content+='\0' * (64 - len(udp_packet_content)) # Append as many null characters as needed
	
	return udp_packet_content

'''
udp_packet_constructor function
Arguments:
	CID, ACK, EOM, data_remaining, content: As specified in lab instructions
Return:
	packet: (binaary) ready packet to be sent to the server
This function construct the packet to be sent to the server
it has the form specified in the UDP protocol section of the lab instructions
CID | ACK | EOM | Data remaining | Content length | Content
'''
def udp_packet_constructor(CID, ACK=True, EOM=False, data_remaining=0, content_length=0, content="Hello from "):
	# First, we need to convert the string to bytes. (struct.pack packs bytes only not strings !) 
	content = bytes(content, 'utf-8')
	CID = bytes(CID, 'utf-8')
	
	# Check source: https://docs.python.org/3/library/struct.html#format-characters
	# struct.pack format explain:
	# ! => big-ending; 	%ds => string with lenght :len(CID) / 64
	# ? => boolean; 	H => unsigned short

	packet = struct.pack('!%ds??HH%ds' % (len(CID), 64),
				CID, ACK, EOM, data_remaining, content_length, content)

	return packet

'''
udp_packet_unpack function
Arguments:
	packet: (bytes) packet received from server on the UDP socket
return:
	data: (list) if containts:
	CID (str) | ACK (bool)| EOM (bool)| Data remaining (int) | Content length (int)| Content (string)
udp_packet_unpack function is used to unpack the UDP packet received from the server
Note that the returned content is padded with null bytes !!!
'''
def udp_packet_unpack(packet, id_length=8, content_len=64):
	# struct.unpack returns a tuple. I casted it to list !
	CID, ACK, EOM, data_remaining, content_length, content = \
				list(struct.unpack('!%ds??HH%ds' % (id_length, content_len), packet))
	# Decode the CID and content from bytes to string before returning them
	CID  = CID.decode('utf-8')
	content = content.decode('utf-8')
	return CID, ACK, EOM, data_remaining, content_length, content

'''
reverse_order function
Argument:
	words: (string) sequence of words to reverse their order. No null bytes at the end are expected !
return:
	reversed_words: (string) the initial words but in reverse order
This funtion is used to reverse the order of the words received from 
the server to resend them back
'''
def reverse_order(words):
	# Extract the words
	list_words = words.split(' ')
	# Reverse the order of the list
	list_words.reverse()
	# Joining the reversed list into a final string
	reversed_words = ' '.join(list_words)

	return reversed_words

'''
encrypt function
Arguments:
	content: (string) udp packet content to encrypt
	key: (string) key to use for encryption
Return:
	cypher: (string) encrypted udp packet content
The encryption consists of XORing each character of the content with
the corresponding character of the key 
'''
def encrypt(content, key):
	cypher = ''

	for [x, y] in zip(content, key):

		cypher+=chr(ord(x) ^ ord(y))

	return cypher

'''
decrypt function
Arguments:
	cypher: (string) cypher content to decrypt
	key: (string) key to use for decryption
Return:
	plain_text: (string) decrepted udp encrypted packet content
The decryption consists of XORing each character of the cypher string with
the corresponding character of the key 
'''
def decrypt(cypher, key):
	plain_text = ''

	for [x, y] in zip(cypher, key):

		plain_text+=chr(ord(x) ^ ord(y))

	return plain_text

'''
tcp_connect function
Arguments:
	TCP_IP: (string) server's tcp_ip address to be used
	TCP_PORT: (integer) server's tcp open port
	MESSAGE: (string) Message to send to the server
return
	data: (binary stirng) server reply message to our sent message
Note that tcp_connection initializes the tcp_ip connection of  the client to the server
the message in encoded into binary string so that it can be sent
'''
def tcp_connect(TCP_IP, TCP_PORT, MESSAGE):
	BUFFER_SIZE = 2048
	# Initialization a socket instance
	# Initialization of client connection parameters
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Defining server IP address and connection port
	s.connect((TCP_IP, TCP_PORT))

	# Send the message to the server. Please note that the message string is converted into bytes
	s.send(MESSAGE.encode('utf-8'))
	# Getting data from server
	data = s.recv(BUFFER_SIZE)
	# Closing the socket once the server responds
	s.close()
	# returning what the server says !
	return data

def udp_connect(UDP_IP, UDP_PORT, packet):
	BUFFER_SIZE = 1024
	# Initiate UDP socket
	clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	# Sending message to the server using UDP protocol
	clientSock.sendto(packet, (UDP_IP, UDP_PORT))

	# bind IP address and port number to server 
	#clientSock.bind((UDP_IP, UDP_PORT))

	# Waiting to receive response from the server
	while True:
		data, _ = clientSock.recvfrom(BUFFER_SIZE)
		if data:
			break

	clientSock.close()
	return data

'''
main funtion
'''
def main():
	# Extracting command line arguments if availabe
	try: 
		TCP_IP = sys.argv[1]
		TCP_PORT = int(sys.argv[2])
	except:
		print('Please make sure to give correct IP address and PORT as command line arguments\n')
		print('Correct invocation of the program:')
		print('python3 Com_project <IP-ADDRESS> <PORT>')
		return


	# Negociating extra features
	print('You want to conenct to ' + str(TCP_IP) + ' using port : '+ str(TCP_PORT))
	print('Please specify the features you want to use for this connection')
	print('Please enter the corresponding number for each feature\nWhen you select all the features you want to use, please enter "e"')
	print('To exit the progam, please enter "q"')
	print('0) No features\t1) Encryption\t2) Multipart\t3)Parity')
	## Getting user input
	# Features are disables by default
	feature_enc = False
	feature_mul = False
	feature_par = False

	accepted_in = ['0', '1', '2', '3', 'q', 'e'] 	# Valid entries of the selection section above
	while True:
		tmp = input()		# Getting user input
		if tmp in accepted_in:	# If user input is a valid entry
			if tmp == 'q': # q ==> close program
				return
			elif tmp == 'e':	# User had gave all the features he wants to use
				break
			else:
				if   tmp == '0':	# Don't use any feature
					break
				if   tmp == '1':
					feature_enc = True
				elif tmp == '2':
					feature_mul = True
				elif tmp == '3':
					feature_par = True
				else:
					print('You are not supposed to see this message !')
					return
		else:
			print('Please enter a valid entry !')

	## The TCP/IP protocol implementation
	'''
	In this section, the program will negociate the features to use with the server
	And it will get the client's identification token and UDP port
	'''

	# If encryption is not selected, this is the initial message is
	MESSAGE = "HELLO \r\n"
	


	## If multipart is selected 
	# do something to the message here!

	## If Parity is selected
	# do something here !

	## If encryption feature is selected, generate keys and embed them into the message
	# Generate keys
	if feature_enc:
		private_keys = generate_keys(key_size=64, nbr_of_keys=20)

		# Getting the ready-to-send-message
		MESSAGE = embed_key_message(private_keys)


	# At this point, the message to be sent to the server should be generated !
	## Let's send the ready message to the server
	# tcp_connect connects to the server and initializes the connection parameter
	data = tcp_connect(TCP_IP, TCP_PORT, MESSAGE)

	## The server returned 'data'. This 'data' should be manipulated according to user-specific selected features
	# So far, only works for no features and feature_enc = True
	# If enc feature was selected, we need the extract the server keys
	if feature_enc:
		# Extracting server's keys from the initialization message ('To be used only if encryption is enabled')
		[client_id, udp_port, server_keys] = extract_server_msg(data, features=1)
	else:
		# Extract cliend id and udp port to use
		[client_id, udp_port, _] = extract_server_msg(data, features=0)

	print(client_id)
	print(udp_port)

	## The UDP protocol implementation

	# Initialization 
	EOM = False		# Initial state of the End of communication flag
	content = "Hello from " + client_id		# First message to send
	msg_length = len(content)

	i=0 	# Used as key counter
	while not EOM:
		# If enc feature was used !
		if feature_enc:
			# Appending null characters to the content of the udp packet of needed
			content = udp_packet_content_padding(content)
			# Encrypt the message (we are using key zero to encrypt the content)
			content = encrypt(content, key=private_keys[i])
	
		# Packet construction
		packet = udp_packet_constructor(CID=client_id, 
									ACK = True,
									EOM = False,
									data_remaining = 0,
									content_length = msg_length, # only for testing !
									content = content)
	
		# Once the packet is constructed, let's send it using UDP protocol
		server_said = udp_connect(UDP_IP = TCP_IP, UDP_PORT=int(udp_port), packet = packet)

		# unpacking the packet received from the server
		CID, ACK, EOM, data_remaining, content_length, content = udp_packet_unpack(server_said)
		print('content from server:\n'+content[0:content_length])
		# Once we get the UDP packet unpacked, let's inverse the order of the content section
		# Note that 'words' is free of null bytes padding
		if not EOM:
			# If ENC feature was enabled, we have to decrypt the content received from the server
			if feature_enc:
				content = decrypt(cypher=content, key=server_keys[i])

			print('Decrypted content from server:\n'+content[0:content_length])
			reversed_words = reverse_order(words= content[0:content_length])
			print('reversed order words: \n' + reversed_words)
			content = reversed_words
			msg_length = len(reversed_words)
			i+=1

	'''
	The following section is the test section
	Please, when you deploy new functions try them in the section below
	Once you make sure that everything runs as it should
	write it above at its meaningful location
	'''

	#print("received data:", data)
	print('\nDone\n')
	
if __name__ == '__main__':
	main()
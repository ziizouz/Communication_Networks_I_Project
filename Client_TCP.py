#!/usr/bin/env python
# Please compile using Python 3
import socket 		# To manage sockets
import sys 			# To extract command line arguments
import ipaddress 	# To check the validaty of the TCP_IP address entered
import secrets		#  for generating cryptographically strong random numbers

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
extract_server_keys
Arguments:
	data: (binary string) it should be the first binary string received from the server
return:
	client_id: (string) the client identification token specified by the server
	udp_port: (string) udp port number on  the server
	server_keys: (list) it contains server keys to be used to decryption
Note that extract_server_keys decode the binary string received into ordinary ASCII string
Then, it splits the string on (\r\n).
the first element is split on (space) to extract the identification token and upd port number
the last elmenents are discarded ('.') and ('') empty character
'''
def extract_server_keys(data):
	tmp = data.decode('ascii').split('\r\n')
	[_, client_id, udp_port] = tmp[0].split(' ')		# First element of the server message is Hello identif udp_port
	server_keys = tmp[1:-2]  # Keys are all the vector elements except the first (identif) last (.)
	
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

def udp_messaging():
	pass

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

def udp_connection(parameters):
	pass

'''
main funtion
'''
def main():
	TCP_IP = '87.92.113.80'
	TCP_PORT =10000
	# Extracting command line arguments if availabe
	if len(sys.argv) > 2:
		TCP_IP = sys.argv[1]
		TCP_PORT = sys.argv[2]

	# Negociating extra features
	print('You want to conenct to ' + str(TCP_IP) + ' using port : '+ str(TCP_PORT))
	print('Please specify the features you want to use for this connection')
	print('Please enter the corresponding number for each feature\nWhen you select all the features you want to use, please enter "q"')
	print('1) Encryption\t2) Multipart\t3)Parity')
	print('\n\n')
	features = []
	# Still needs some work above !!
	#MESSAGE = "HELLO \r\n"
	#MESSAGE = "HELLO ENC\r\n"
	
	## If encryption feature is selected, generate keys and embed them into the message
	# Generate keys
	private_keys = generate_keys(key_size=64, nbr_of_keys=20)

	# Getting the ready-to-send-message
	MESSAGE = embed_key_message(private_keys)

	# tcp_connect connects to the server and initializes the connection parameter
	data = tcp_connect(TCP_IP, TCP_PORT, MESSAGE)

	# Extracting server's keys from the initialization message ('To be used only if encryption is enabled')
	[client_id, udp_port, server_keys] = extract_server_keys(data)

	# some random message to encrypt (just for testing, it should be udp packet)
	udp_packet_content = 'Hello from ' + client_id
	
	# Appending null characters to the content of the udp packet of needed
	upd_packet_content = udp_packet_content_padding(udp_packet_content)
	
	# Encrypt the message (we are using key zero to encrypt the content)
	cypher = encrypt(upd_packet_content, key=private_keys[0])
	
	# Decryption of the cypher message
	plain_text = decrypt(cypher, key=private_keys[0])
	
	#print("received data:", data)
	print('\nDone\n')
	
if __name__ == '__main__':
	main()
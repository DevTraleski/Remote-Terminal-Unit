from coapthon.client.helperclient import HelperClient
from coapthon.messages.message import Message
from coapthon.messages.request import Request
from coapthon import defines

from Crypto.Cipher import AES

import os.path
import sys
import json
import binascii
import base64
import hashlib
import random

def setup():
	
	db = open("db", "w+")

	serial = 'serial' + str(sys.argv[1])
	nonce = str(base64.b32encode(sys.argv[1].encode('utf-8')))[2:-1]

	db.write('serial:' + str(serial) + '\n')
	db.write('nonce:' + nonce + '\n')
	db.write('info2:' + 'a'*2 + '\n')
	db.write('info4:' + 'a'*4 + '\n')
	db.write('info8:' + 'a'*8 + '\n')
	db.write('info16:' + 'a'*16 + '\n')
	db.write('info32:' + 'a'*32 + '\n')
	db.write('info64:' + 'a'*64 + '\n')
	db.write('info128:' + 'a'*128 + '\n')

	gatewayAddress = '172.0.17.5'
	gatewayPort = 1337

	client = HelperClient(server=(gatewayAddress, int(gatewayPort)))
			
	request = Request()
	request.destination = client.server
	request.code = defines.Codes.GET.number
	request.uri_path = 'setup/'
	request.payload = serial

	response = client.send_request(request)
	client.stop()

	#Decrypt
	payload = response.payload
	dict = json.loads(payload)

	#Check for error
	if 'error' in dict.keys():
		print("Error: " + dict['error'])
	else:
		m = hashlib.md5()
		m.update(nonce.encode("UTF-8"))
		hashKey = m.hexdigest()[:16]
		
		IV = binascii.unhexlify(dict['iv'])
		data = binascii.unhexlify(dict['data'])

		decipher = AES.new(hashKey, AES.MODE_CBC, IV=IV)
		jsonStr = decipher.decrypt(data)
		jsonStr = jsonStr[:-jsonStr[-1]]

		dict = json.loads(jsonStr.decode('utf-8'))

		db.write("dtlsk:" + dict['dtlsk'] + '\n')
		db.write("gnonce:" + dict['gnonce'] + '\n')

		print("Setup complete")

if os.path.isfile('./db') == True:
	print("No need to setup start server")
else:
	setup()

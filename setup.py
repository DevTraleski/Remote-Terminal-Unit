from coapthon.client.helperclient import HelperClient
from coapthon.messages.message import Message
from coapthon.messages.request import Request
from coapthon import defines

from Crypto.Cipher import AES

import sys
import json
import binascii

db = open("db", "r+")

data = db.readlines()
database = {}

for line in data:
	info = line.split(":")
	database[info[0]] = info[1]

serial = database['serial'][:-1]
nonce = database['nonce'][:-1]

gatewayAddress = sys.argv[1]
gatewayPort = sys.argv[2]

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
	IV = binascii.unhexlify(dict['iv'])
	data = binascii.unhexlify(dict['data'])

	decipher = AES.new(nonce, AES.MODE_CBC, IV=IV)
	jsonStr = decipher.decrypt(data)
	jsonStr = jsonStr[:-jsonStr[-1]]

	dict = json.loads(jsonStr.decode('utf-8'))

	db.write("dtlsk:" + dict['dtlsk'] + '\n')
	db.write("gnonce:" + dict['gnonce'] + '\n')

	print("Setup complete")

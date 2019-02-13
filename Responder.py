from coapthon.client.helperclient import HelperClient
from coapthon.messages.message import Message
from coapthon.messages.request import Request
from coapthon.messages.response import Response
from coapthon import defines

from Crypto.Cipher import AES

import time
import datetime
import binascii
import hashlib
import pyotp
import json
import os

class Responder():
	
	dtlsKey = "Null"
	nonce = "Null"
	groupNonce = "Null"
	lmk = "Null"
	database = {}

	def __init__(self):
		with open("db", "r") as f:
			data = f.readlines()

		for line in data:
			info = line.split(":")
			self.database[info[0]] = info[1]

		self.groupNonce = self.database['gnonce'][:-1]
		self.nonce = self.database['nonce'][:-1]
		self.lmk = self.database['lmk'][:-1]
		self.dtlsKey = self.database['dtlsk'][:-1]

	def respond(self, request):
		jsonStr = request.payload
		#jsonStr = request
		dict = json.loads(jsonStr)
	
		hotp = pyotp.HOTP(self.groupNonce)
		
		print("Time Stamp: " + dict['timestamp'])		
		timeCode = dict['timestamp'].replace(":", "")
		timeCode = timeCode.replace(" ", "")
		timeCode = timeCode.replace("-", "")
		print(timeCode)
		timeCode = int(timeCode)		

		groupKey = hotp.at(timeCode)
		m = hashlib.md5()
		m.update(groupKey.encode("UTF-8"))
		hashedKey = m.hexdigest()[:16]
		print("Group Key: " + groupKey)
		print("Hashed Key: " + hashedKey)
		
		print("Hexed IV: " + dict['iv'])
		IV = binascii.unhexlify(dict['iv'])
		print("Unhexed IV: " + str(IV))
		decipher = AES.new(hashedKey, AES.MODE_CBC, IV)
		print("Rcv Data: " + dict['data'])
		unhexData = binascii.unhexlify(dict['data'])
		print("Unhexed Data: " + str(unhexData))
		plainText = decipher.decrypt(unhexData)
		plainText = plainText[:-plainText[-1]]
		plainText = plainText.decode("utf-8")
		print("Decoded without padding: " + plainText)

		if plainText in self.database.keys():
			#Value, encrypt, json, return
			value = self.database[plainText]			

			totp = pyotp.TOTP(self.nonce)
			totpKey = totp.now()
			print("TOTP Key: " + totpKey)
			m = hashlib.md5()
			m.update(totpKey.encode("UTF-8"))
			hashKey = m.hexdigest()[:16]
			
			IV = os.urandom(16)
			encryptor = AES.new(hashKey, AES.MODE_CBC, IV=IV)
			length = 16 - (len(value) % 16)
			data = bytes([length])*length
			value += data.decode("utf-8")
			cryptedValue = encryptor.encrypt(value)

			dados = { 'data' : str(binascii.hexlify(cryptedValue).upper())[2:-1],
				'timestamp' : dict['timestamp'],
				'iv' : str(binascii.hexlify(IV).upper())[2:-1] }
			payload = json.dumps(dados)
			
			#Send different request to Gateway wait for ACK and return
			client = HelperClient(server=(request.source[0], 1337))
			
			request = Request()
			request.destination = client.server
			request.code = defines.Codes.POST.number
			request.uri_path = 'respond/'
			request.payload = payload

			client.send_request(request)
			client.stop()

			return "OK"
			

#print(Responder().respond('{"data": "C0B5794C2AB6F642743697D572F4BFCD", "timestamp": "2019-02-12 20:30:07", "iv": "636253E0C6D15E6CA7B6266ADD0136C6"}'))

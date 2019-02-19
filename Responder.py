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
	serial = "Null"
	database = {}

	def __init__(self):
		with open("db", "r") as f:
			data = f.readlines()

		for line in data:
			info = line.split(":")
			self.database[info[0]] = info[1]

		self.groupNonce = self.database['gnonce'][:-1]
		self.nonce = self.database['nonce'][:-1]
		self.dtlsKey = self.database['dtlsk'][:-1]
		self.serial = self.database['serial'][:-1]

	def decrypt(self):
		print("Decrypting")

	def _encrypt(self, value):
		print("value: " + value)

		totp = pyotp.TOTP(self.nonce)
		now = time.time()
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
			
		print(cryptedValue)
			
		dados = { 'data' : str(binascii.hexlify(cryptedValue).upper())[2:-1],
			'timestamp' : now,
			'iv' : str(binascii.hexlify(IV).upper())[2:-1],
			'serial' : self.serial }
		lastLayer = json.dumps(dados)

		print("Deepest layer: " + lastLayer)

		#Second encryption wrap
		IV = os.urandom(16)
		encryptor = AES.new(self.dtlsKey, AES.MODE_CBC, IV=IV)
		length = 16 - (len(lastLayer) % 16)
		data = bytes([length])*length
		lastLayer += data.decode("utf-8")
		secondCrypt = encryptor.encrypt(lastLayer)

		dados = { 'data' : str(binascii.hexlify(secondCrypt).upper())[2:-1],
			'iv' : str(binascii.hexlify(IV).upper())[2:-1],
			'serial' : self.serial }
		payload = json.dumps(dados)
		return payload

	def _send(self, source, path, code, payload):
		client = HelperClient(server=(source, 1337))
		#client = HelperClient(server=('172.0.17.5', 1337))
			
		request = Request()
		request.destination = client.server
		request.code = code
		request.uri_path = path
		request.payload = payload
		
		print("Send request: " + request.pretty_print())

		client.send_request(request)
		client.stop()


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

		print(plainText)

		if plainText in self.database.keys():
			#Value, encrypt, json, return		
			payload = self._encrypt(self.database[plainText][:-1])
			self._send(request.source[0], 'respond/', defines.Codes.POST.number, payload)
			return "OK"

	def alert(self):
		payload = self._encrypt('ALERT')
		self._send('172.0.17.5', 'alert/', defines.Codes.POST.number, payload)
		print("ALERT")
		

#print(Responder().respond('{"data": "C0B5794C2AB6F642743697D572F4BFCD", "timestamp": "2019-02-12 20:30:07", "iv": "636253E0C6D15E6CA7B6266ADD0136C6"}'))

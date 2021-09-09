
from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT  = 2.0
TRIES    = 2

#below is a function to help E.C#1 - to calculate the min, max, and avg rtt
def getRttData(curRtt, rttData):
	#logic: 
	# get the current RTT - compare it to see if it is smaller than the min, else check max,
	# update as necessary,
	# then add once to the totalRTT
	# recalculate the avg and update.

	#if its the first time.
	if(rttData[0] == 0):
		rttData[0] = curRtt

	if(rttData[1] == 0):
		rttData[1] = curRtt

	if(curRtt <= rttData[0]):
		rttData[0] = curRtt
	elif(curRtt >= rttData[1]):
		rttData[1] = curRtt

	rttData[3] += curRtt
	rttData[4] += 1
	rttData[2] = rttData[3] / rttData[4] 




def checksum(string):
	csum = 0
	countTo = (len(string) // 2) * 2
	count = 0
	while count < countTo:
		thisVal = ord(string[count+1]) * 256 + ord(string[count])
		csum = csum + thisVal
		csum = csum & 0xffffffff
		count = count + 2

	if countTo < len(string):
		csum = csum + ord(string[len(string) - 1])
		csum = csum & 0xffffffff

	csum = (csum >> 16) + (csum & 0xffff)
	csum = csum + (csum >> 16)
	answer = ~csum
	answer = answer & 0xffff
	answer = answer >> 8 | (answer << 8 & 0xff00)
	return answer

def build_packet(data_size):
	# First, make the header of the packet, then append the checksum to the header,
	# then finally append the data

	# Donâ€™t send the packet yet, just return the final packet in this function.
	# So the function ending should look like this
	# Note: padding = bytes(data_size)
	#http://www.networksorcery.com/enp/protocol/icmp.html from slack, it was help.
	# from slack, build a header and data, then checksum(header and data), make a new header with check, then add data, and padding.
	# header has TYPE, Code, checkSum, ID, sequence
	#variables
	#icmp_type = 8 was already established as global
	code = 0
	checkVal = 0
	headerId = 12 # only for echo reply
	headerSeq = 1 # seq value return
	
	# Below are the variation of testing i tried for data before settling on time - to complete the ICMP request == 0 for the final destin
	#data = bytes("test", 'ISO-8859-1')
	#data = struct.pack("d", 12345)
	data = struct.pack("d", time.time())
	
	# packing the header with the inital data.
	#https://www.journaldev.com/17401/python-struct-pack-unpack
	header = struct.pack("BBHHH", ICMP_ECHO_REQUEST, code, checkVal, headerId, headerSeq)


	#update the new packet
	checkVal = checksum(header.decode('ISO-8859-1')+data.decode('ISO-8859-1'))
	#print(checkVal
	# properly reformat the checkVal again. 
	checkVal = htons(checkVal)
	header = struct.pack("BBHHH", ICMP_ECHO_REQUEST, code, checkVal, headerId, headerSeq)
	#adding padding because we are not unpacking with the right buffer size...
	padding = bytes(data_size)
	packet = header + data + padding
	return packet

def get_route(hostname,data_size):
	timeLeft = TIMEOUT
	#help printing out name and ip desination
	ipName = gethostbyname(hostname)
	print("traceroute: " + hostname + " - " + ipName)
	
	#variables to help calculate RTT for E.C#1
	rttData = [0,0,0,0,0, 0]
	for ttl in range(1,MAX_HOPS):
		for tries in range(TRIES):
			destAddr = gethostbyname(hostname)
			# SOCK_RAW is a powerful socket type. For more details:   http://sock-raw.org/papers/sock_raw
			#Fill in start
			# Make a raw socket named mySocket
			# from http://sock-raw.org/papers/sock_raw 
			mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
			#Fill in end

			# setsockopt method is used to set the time-to-live field.
			mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
			mySocket.settimeout(TIMEOUT)
			try:
				d = build_packet(data_size)
				#print("built packet is -", d)
				#FOR E.C1 - we will count how many packet are sent out via out rttData list on part 5
				rttData[5] += 1
				mySocket.sendto(d, (hostname, 0))
				t= time.time()
				startedSelect = time.time()
				whatReady = select.select([mySocket], [], [], timeLeft)
				howLongInSelect = (time.time() - startedSelect)
				if whatReady[0] == []: # Timeout
					print("  *        *        *    Request timed out.")
				recvPacket, addr = mySocket.recvfrom(1024)
				timeReceived = time.time()
				timeLeft = timeLeft - howLongInSelect
				if timeLeft <= 0:
					print("  *        *        *    Request timed out.")
				#print("timeout", timeout)
			except timeout:
				continue

			else:
				#Fill in start
				#Fetch the icmp type from the IP packet
				#bytes unpack the same way it was packed.
				#https://piazza.com/class/k892xt0vqjs3x5?cid=264 - to keep in mind.
				types, code, checkVal, recvId, recvSeq = struct.unpack('BBHHH', recvPacket[20:28])
				#Fill in end
				
				if types == 11:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived -t)*1000, addr[0]))
					getRttData((timeReceived -t)*1000, rttData)
					#print(rttData)
				elif types == 3:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived-t)*1000, addr[0]))
					getRttData((timeReceived -t)*1000, rttData)
					#print(rttData) 
				elif types == 0:
					#note to self, consider adding padding? to unpack the data when it reached the destination.
					# note to self, you need to pack your data as type d, 
					# https://piazza.com/class/k892xt0vqjs3x5?cid=276
					# timeRec - timeSent - to get total time... 
					# and this is asking for the data piece, so "string test and any random number will not work.".
					# timeRecvieved is time.time(), thus data will be time.time() for packing.
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					#print(timeSent)
					#print(timeReceived)
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived - timeSent)*1000, addr[0]))
					getRttData((timeReceived -timeSent)*1000,rttData)
					#print out the summary data: for E.C #1
					print("* * * SUMMARY * * * ")
					print("Minimum RTT - %.0f ms" %rttData[0])
					print("Max RTT - %.0f ms" %rttData[1])
					print("Average RTT - %.0f ms" %rttData[2])
					# https://www.techwalla.com/articles/how-to-calculate-packet-loss-ratio
					temp = (rttData[5] - rttData[4])/rttData[5]
					#print(temp)
					print("Packet loss rate - " + "{:.1%}".format(temp))# basically how many packet we got back // how many we sent out.
					return

				else:
					print("error")
				break
			finally:
				mySocket.close()


print('Argument List: {0}'.format(str(sys.argv)))

data_size = 0
if len(sys.argv) >= 2:
	data_size = int(sys.argv[1])
# CA - North America
get_route("google.com",data_size)


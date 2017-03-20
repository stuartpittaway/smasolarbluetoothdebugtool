#!/opt/bin/python2.7

# Run this script like this...
# python SMASolarInverterPacketDebug.py 00:80:25:1D:AC:53 0000

# More useful background reading on here (Alan)
# https://groups.google.com/forum/#!topic/sma-bluetooth/UP4Tp8Ob3OA


import bluetooth
import array
import math
import time
import csv
from collections import namedtuple
from datetime import date, datetime
import argparse
import sys, traceback
import requests

class SMANET2PlusPacket:
    """Holds a second type of SMA protocol packet"""

    def reset(self):
        self.FCSChecksum = 0xffff
        self.packet = bytearray()

    def __init__(self, ctrl1=0, ctrl2=0, packetcount=0, InverterCodeArray=bytearray(), a=0, b=0, c=0):
        #print "Creating instance of SMANET2PlusPacket"

        self.reset()

        self.fcstab = array.array("i", [
               0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf, 0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7, 0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e, 0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
               0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd, 0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5, 0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c, 0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
               0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb, 0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3, 0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a, 0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
               0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9, 0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1, 0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738, 0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
               0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7, 0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff, 0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036, 0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
               0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5, 0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd, 0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134, 0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
               0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3, 0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb, 0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232, 0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
               0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1, 0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9, 0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330, 0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
            ])

        if (ctrl1 != 0 or ctrl2 != 0):
            # 0xFF036065 SMA Net Telegram Frame (SMADATA2+)
            self.pushRawByteArray(bytearray([0xff , 0x03, 0x60 , 0x65, ctrl1, ctrl2 ]));
            #self.pushRawByteArray(bytearray([ 0x00, 0x00, 0xff, 0xff, 0xff, 0xff ]))

            #Ziel SusyID (FFFFF = any SusyID)
            self.pushRawByteArray(bytearray([ 0xff, 0xff ]))
            #Ziel Serial (FFFFFFFF is any)
            self.pushRawByteArray(bytearray([ 0xff, 0xff, 0xff, 0xff ]))
            #Ctrl2
            self.pushRawByteArray(bytearray([a, b]));
            #Eigene SusyID (FFFFF = any SusyID) + Eigene Serial (FFFFFFFF is any)
            self.pushRawByteArray(InverterCodeArray);
            #Ctrl2
            self.pushRawByteArray(bytearray([0x00 , c ]))
            #self.pushRawByteArray(bytearray([0x00 , 0x00 , 0x00 , 0x00 ]))
            self.pushLong(0x00000000)
            #This should be two bytes!
            #self.pushRawByteArray(bytearray([packetcount]))
            self.pushShortByte(packetcount |  0x00008000)



    def getFourByteLong(self, offset):
        value = self.packet[offset] * math.pow(256, 0)
        value += self.packet[offset + 1] * math.pow(256, 1)
        value += self.packet[offset + 2] * math.pow(256, 2)
        value += self.packet[offset + 3] * math.pow(256, 3)
        return long(value);

    def getTwoByteLong(self, offset):
        value = self.packet[offset] * math.pow(256, 0)
        value += self.packet[offset + 1] * math.pow(256, 1)
        return long(value);

    def getThreeByteDouble(self, offset):
        # check if all FFs which is a null value
        if self.packet[offset + 0] == 0xff and self.packet[offset + 1] == 0xff and self.packet[offset + 2] == 0xff:
            return None
        else:
            return self.packet[offset + 0] * math.pow(256, 0) + self.packet[offset + 1] * math.pow(256, 1) + self.packet[offset + 2] * math.pow(256, 2)

    def getFourByteDouble(self, offset):
        # check if all FFs which is a null value
        if self.packet[offset + 0] == 0xff and self.packet[offset + 1] == 0xff and self.packet[offset + 2] == 0xff and self.packet[offset + 3] == 0xff:
            return None
        else:
            return self.packet[offset + 0] * math.pow(256, 0) + self.packet[offset + 1] * math.pow(256, 1) + self.packet[offset + 2] * math.pow(256, 2) + self.packet[offset + 3] * math.pow(256,3)


    def get8ByteFloat(self, offset):
        value = self.packet[offset] * math.pow(256, 0)
        value += self.packet[offset + 1] * math.pow(256, 1)
        value += self.packet[offset + 2] * math.pow(256, 2)
        value += self.packet[offset + 3] * math.pow(256, 3)
        value += self.packet[offset + 4] * math.pow(256, 4)
        value += self.packet[offset + 5] * math.pow(256, 5)
        value += self.packet[offset + 6] * math.pow(256, 6)
        value += self.packet[offset + 7] * math.pow(256, 7)
        return value;

    def getArray(self):
        return self.packet;

    def getPacketCounter(self):
        return self.packet[26]

    def getDestinationAddress(self):
        return self.packet[14:20]

    def totalPayloadLength(self):
        return len(self.packet)

    def totalCalculatedPacketLength(self):
        return self.packet[4] * 4 + 8;

    def isPacketFull(self):
        return (4 + self.totalPayloadLength()) == self.totalCalculatedPacketLength()

    def validateChecksum(self, checksum):
        myfcs = self.FCSChecksum ^ 0xffff
        return checksum == myfcs

    def getFragment(self):
        return self.packet[24]

    def getTwoByteuShort(self, offset):
        value = self.packet[offset] * math.pow(256, 0) + self.packet[offset + 1] * math.pow(256, 1)
        return value

    def errorCode(self):
        return self.getTwoByteuShort(22)

    def calculateFCS(this):
        myfcs = 0xffff
        for bte in packet:
            myfcs = (myfcs >> 8) ^ self.fcstab[(myfcs ^ bte) & 0xff]

        myfcs ^= 0xffff
        print "CalculateFCS={0:04x}".format(myfcs)

    def pushRawByteArray(self, barray):
        for bte in barray: self.pushRawByte(bte)

    def pushRawByte(self, value):
        self.FCSChecksum = (self.FCSChecksum >> 8) ^ self.fcstab[(self.FCSChecksum ^ value) & 0xff]
        self.packet.append(value)

    def pushShortByte(self, value):
        #Sends two byte short in little endian format
        self.pushRawByte(value & 0xFF)
        self.pushRawByte((value >> 8) & 0xFF)

    def pushLongs(self, value1,value2,value3):
        self.pushLong(value1)
        self.pushLong(value2)
        self.pushLong(value3)

    def pushLong(self, value):
        #Sends two byte short in little endian format
        self.pushRawByte(value & 0xFF)
        self.pushRawByte((value >> 8) & 0xFF)
        self.pushRawByte((value >> 16) & 0xFF)
        self.pushRawByte((value >> 24) & 0xFF)

    def getBytesForSending(self):
        outputpacket = bytearray()

        realLength=0
        # //Header byte
        outputpacket.append(0x7e)
        realLength+=1

        # //Copy packet to output escaping values along the way
        for value in self.packet:
            if (value == 0x7d) or (value == 0x7e) or (value == 0x11) or (value == 0x12) or (value == 0x13):
                outputpacket.append(0x7d)  # //byte to indicate escape character
                outputpacket.append(value ^ 0x20)
                realLength+=1
            else:
                outputpacket.append(value)
                realLength+=1

        self.FCSChecksum ^= 0xffff  # complement

        # Checksum
        outputpacket.append(self.FCSChecksum & 0x00ff)
        realLength+=1
        outputpacket.append((self.FCSChecksum >> 8) & 0x00ff)
        realLength+=1

        # Trailer byte
        outputpacket.append(0x7e)
        realLength+=1

        #print "Packet length {0} vs {1}".format(realLength,self.totalCalculatedPacketLength())

        if (self.totalCalculatedPacketLength()!=realLength):
            raise Exception("Packet length is incorrect {0} vs {1}".format(realLength,self.totalCalculatedPacketLength()))

        return outputpacket

    def debugViewPacket(self):
        pos = 0;

        print "L2  ARRAY LENGTH = {0}".format(len(self.packet))
        print "L2 {0:04x}  START = {1:02x}".format(pos, 0x7e)
        pos += 0
        print "L2 {0:04x}  Header= {1:02x} {2:02x} {3:02x} {4:02x}".format(pos, self.packet[pos + 0],
                                                                           self.packet[pos + 1], self.packet[pos + 2],
                                                                           self.packet[pos + 3])


        if (self.packet[pos+0]==0xff and self.packet[pos+1]==0x03 and self.packet[pos+2]==0x60 and self.packet[pos+3]==0x65):
            print "0xFF036065 SMA Net Telegram Frame (SMADATA2+)"

        pos += 4
        print "L2 {0:04x}  Length= {1:02x}  ={2} bytes".format(pos, self.packet[pos], (self.packet[pos] * 4) + 8)
        pos += 1
        print "L2 {0:04x}       ?= {1:02x}".format(pos, self.packet[pos])
        pos += 1
        print "L2 {0:04x}  susyid= {1:02x} {2:02x}".format(pos, self.packet[pos + 0],
                                                                                           self.packet[pos + 1],
                                                                                        )
        pos += 2
        print "L2 {0:04x}    Add1= {1:02x} {2:02x} {3:02x} {4:02x}".format(pos, self.packet[pos + 0],
                                                                                           self.packet[pos + 1],
                                                                                           self.packet[pos + 2],
                                                                                           self.packet[pos + 3],
                                                                                          )
        pos += 4
        print "L2 {0:04x}  ArchCd= {1:02x}".format(pos, self.packet[pos])
        pos += 1
        print "L2 {0:04x}    zero= {1:02x}".format(pos, self.packet[pos])
        pos += 1
        print "L2 {0:04x}  susyid= {1:02x} {2:02x}".format(pos, self.packet[pos + 0],
                                                                                           self.packet[pos + 1],
                                                                                        )
        pos += 2
        print "L2 {0:04x}    Add2= {1:02x} {2:02x} {3:02x} {4:02x}".format(pos, self.packet[pos + 0],
                                                                                           self.packet[pos + 1],
                                                                                           self.packet[pos + 2],
                                                                                           self.packet[pos + 3],
                                                                                          )
        pos += 4
        print "L2 {0:04x}    zero= {1:02x} {2:02x}".format(pos, self.packet[pos + 0], self.packet[pos + 1])
        pos += 2
        print "L2 {0:04x}   ERROR= {1:02x} {2:02x}".format(pos, self.packet[pos + 0], self.packet[pos + 1])
        pos += 2
        print "L2 {0:04x} Fragmnt= {1:02x}".format(pos, self.packet[pos])
        pos += 1
        print "L2 {0:04x}       ?= {1:02x}".format(pos, self.packet[pos])
        pos += 1
        print "L2 {0:04x} Counter= {1:02x}{2:02x}".format(pos, self.packet[pos], self.packet[pos + 1])
        pos += 2

        print "Command= {0:04x}".format(self.getFourByteLong(pos))
        pos += 4
        print "  First= {0:04x}".format(self.getFourByteLong(pos))
        pos += 4
        print "   Last= {0:04x}".format(self.getFourByteLong(pos))
        pos += 4

        s = ""
        for j in range(pos, len(self.packet)):
            if (j % 4 == 0):
                s += "\n    %08x: " % j

            s += "%02x " % self.packet[j]

        print "  L2 Payload= %s" % s
        myfcs = self.FCSChecksum ^ 0xffff
        print "L2 Checksu= {0:02x} {1:02x}".format(myfcs & 0x00ff, (myfcs >> 8) & 0x00ff)
        print "L2    END = {0:02x}".format(0x7e)


class SMABluetoothPacket:
    def __str__(self):
        return "I am an instance of SMABluetoothPacket"

    def getLevel2Checksum(self):
        return self.UnescapedArray[len(self.UnescapedArray) - 2] * 256 + self.UnescapedArray[len(self.UnescapedArray) - 3]

    def lastByte(self):
        return self.UnescapedArray[len(self.UnescapedArray) - 1]

    def getLevel2Payload(self):
        skipendbytes = 0
        startbyte = 0

        if self.UnescapedArray[0] == 0x7e:
            startbyte = 1

        if self.lastByte() == 0x7e:
            skipendbytes = 3

        # Skip the first 3 bytes, they are the command code 0x0001 and 0x7E start byte
        # print "FirstByte={0:02x} LastByte={1:02x}  startbyte={2} skipendbytes={3}".format(self.UnescapedArray[0],self.lastByte(),startbyte,skipendbytes)

        l = len(self.UnescapedArray) - skipendbytes
        # print "Copying array from {0} to {1}".format(startbyte,l)
        #LogMessageWithByteArray("Copy Array", self.UnescapedArray[startbyte:l])
        return self.UnescapedArray[startbyte:l]

    def pushRawByteArray(self, barray):
        # Raw byte array
        for bte in barray: self.pushRawByte(bte)

    def pushRawByte(self, value):
        # Accept a byte of ESCAPED data (ie. raw byte from Bluetooth)
        self.UnescapedArray.append(value)
        self.RawByteArray.append(value)

    def pushUnescapedByteArray(self, barray):
        for bte in barray: self.pushUnescapedByte(bte)

    def pushUnescapedByte(self, value):
        # Store the raw byte
        self.UnescapedArray.append(value)

        if value == 0x7d or value == 0x7e or value == 0x11 or value == 0x12 or value == 0x13:
            self.RawByteArray.append(0x7d)  # byte to indicate escape character
            self.RawByteArray.append(value ^ 0x20)
        else:
            self.RawByteArray.append(value)

    def setChecksum(self):
        self.header[3] = self.header[0] ^ self.header[1] ^ self.header[2]

    def finish(self):
        # Not seen any packets over 256 bytes, so zero second byte (needs to be fixed LOL!)
        self.header[1] = len(self.RawByteArray) + self.headerlength
        self.header[2] = 0
        self.setChecksum()
        # Just in case!
        if self.ValidateHeaderChecksum() == False:
            raise Exception("Invalid header checksum when finishing!")

    def pushEscapedByte(self, value):
        previousUnescapedByte = 0

        if len(self.RawByteArray) > 0:
            previousUnescapedByte = self.RawByteArray[ len(self.RawByteArray) - 1 ];

        # Store the raw byte as it was received into RawByteArray
        self.RawByteArray.append(value)

        # did we receive the escape char in previous byte?
        if (len(self.RawByteArray) > 0 and previousUnescapedByte == 0x7d):
            # print "Escaped {0:02x} into {1:02x}".format(value,value ^ 0x20)
            self.UnescapedArray[len(self.UnescapedArray) - 1] = value ^ 0x20
        else:
            # Unescaped array is same as raw array
            self.UnescapedArray.append(value)

    def sendPacket(self, btSocket):
        m = bytearray(str(self.header) + str(self.SourceAddress) + str(self.DestinationAddress) + str(self.cmdcode) + str(self.RawByteArray))
        LogMessageWithByteArray("Sending message ", m)
        l = btSocket.send(str(self.header) + str(self.SourceAddress) + str(self.DestinationAddress) + str(self.cmdcode) + str(self.RawByteArray))
        #print "Sent message containing %d bytes" % l


    def DisplayPacketDebugInfo(self, Message):
        s = ""
        i = 0
        s += "[{0}] [{1}]\n".format(Message, "**RAW** Packet dump")
        s += "    {0:08x}: {1:x} Header\n".format(i, self.header[i])
        i += 1
        s += "    {0:08x}: {2:02x} {1:02x} Length\n".format(i, self.header[i], self.header[i + 1])
        i += 2
        s += "    {0:08x}: {1:02x} Checksum\n".format(i, self.header[i])
        i += 1
        s += "    {0:08x}: {6:02x}{5:02x}{4:02x}{3:02x}{2:02x}{1:02x} Source address\n".format(i, self.SourceAddress[0],
                                                                                               self.SourceAddress[1],
                                                                                               self.SourceAddress[2],
                                                                                               self.SourceAddress[3],
                                                                                               self.SourceAddress[4],
                                                                                               self.SourceAddress[5])
        i += 6
        s += "    {0:08x}: {6:02x}{5:02x}{4:02x}{3:02x}{2:02x}{1:02x} Destination address\n".format(i,
                                                                                                    self.DestinationAddress[
                                                                                                    0],
                                                                                                    self.DestinationAddress[
                                                                                                    1],
                                                                                                    self.DestinationAddress[
                                                                                                    2],
                                                                                                    self.DestinationAddress[
                                                                                                    3],
                                                                                                    self.DestinationAddress[
                                                                                                    4],
                                                                                                    self.DestinationAddress[
                                                                                                    5])
        i += 6
        s += "    {0:08x}: {1:04x} Command\n".format(i, self.CommandCode())
        i += 2

        for j in range(0, len(self.RawByteArray)):
            if (j % 16 == 0):
                s += "\n    %08x: " % j

            s += "%02x " % self.RawByteArray[j]
            i += 1

        s += "\n"

        if self.containsLevel2Packet():
            s += "*** LEVEL 2 PACKET IDENTIFIED ****\n"

        return s

    def containsLevel2Packet(self):
        if len(self.UnescapedArray) < 5:
            return False

        return (self.UnescapedArray[0] == 0x7e and
                self.UnescapedArray[1] == 0xff and
                self.UnescapedArray[2] == 0x03 and
                self.UnescapedArray[3] == 0x60 and
                self.UnescapedArray[4] == 0x65)

    def CommandCode(self):
        return self.cmdcode[0] + (self.cmdcode[1] * 256)

    def setCommandCode(self, byteone, bytetwo):
        self.cmdcode = bytearray([byteone, bytetwo])

    def getByte(self, indexfromstartofdatapayload):
        return self.UnescapedArray[indexfromstartofdatapayload]

    def pushEscapedByteArray(self, barray):
        for bte in barray: self.pushEscapedByte(bte)

    def TotalUnescapedPacketLength(self):
        return len(self.UnescapedArray) + self.headerlength


    def TotalRawPacketLength(self):
        return self.header[1] + (self.header[2] * 256)


    def TotalPayloadLength(self):
        return self.TotalRawPacketLength() - self.headerlength


    def ValidateHeaderChecksum(self):
        # Thanks to
        # http://groups.google.com/group/sma-bluetooth/browse_thread/thread/50fe13a7c39bdce0/2caea56cdfb3a68a#2caea56cdfb3a68a
        # for this checksum information !!
        return  (self.header[0] ^ self.header[1] ^ self.header[2] ^ self.header[3]) == 0


    def __init__(self, length1, length2, checksum=0, cmd1=0, cmd2=0, SourceAddress=bytearray, DestinationAddress=bytearray()):
        self.headerlength = 18
        self.SourceAddress = SourceAddress
        self.DestinationAddress = DestinationAddress

        self.header = bytearray()
        self.header.append(0x7e)
        self.header.append(length1)
        self.header.append(length2)
        self.header.append(checksum)

        # Create our array to hold the payload bytes
        self.RawByteArray = bytearray()
        self.UnescapedArray = bytearray()
        self.setCommandCode(cmd1, cmd2)

        if (checksum > 0) and (self.ValidateHeaderChecksum() == False):
            raise Exception("Invalid header checksum!")

        # print "SMABluetoothPacket class initiated"


def ReadLevel1PacketFromBluetoothStream(btSocket,mylocalBTAddress=bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])):
    while True:
        #print "Waiting for SMA level 1 packet from Bluetooth stream"

        start = btSocket.recv(1)

        # Need to add in some timeout stuff here
        while (start != '\x7e'):
            start = btSocket.recv(1)

        length1 = btSocket.recv(1)
        length2 = btSocket.recv(1)
        checksum = btSocket.recv(1)
        SrcAdd = bytearray(btSocket.recv(6))
        DestAdd = bytearray(btSocket.recv(6))

        packet = SMABluetoothPacket(length1, length2, checksum, btSocket.recv(1), btSocket.recv(1), SrcAdd,
                                    DestAdd)

        # Read the whole byte stream unaltered (this contains ESCAPED characters)
        b = bytearray(btSocket.recv(packet.TotalPayloadLength()))

        # Populate the SMABluetoothPacket object with the bytes
        packet.pushEscapedByteArray(b);

        # Tidy up the packet lengths
        packet.finish();

        # Output some progress indicators
        #print "Received Level 1 BT packet cmd={1:04x}h len={0:04x}h bytes".format(packet.TotalPayloadLength(), packet.CommandCode())
        #print packet.DisplayPacketDebugInfo("Received")
        #print ("*")

        if DestAdd == mylocalBTAddress and packet.ValidateHeaderChecksum():
            break

    return packet


def readSMABluetoothPacket(btSocket, waitPacketNumber=0, waitForPacket=False, mylocalBTAddress=bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])):
    #if waitForPacket:
    #    print "Waiting for reply to packet number {0:02x}".format(waitPacketNumber)
    #else:
    #    print "Waiting for reply to any packet"

    bluetoothbuffer = ReadLevel1PacketFromBluetoothStream(btSocket,mylocalBTAddress)

    v = namedtuple("SMAPacket", ["levelone", "leveltwo"], verbose=False)
    v.levelone = bluetoothbuffer

    if bluetoothbuffer.containsLevel2Packet() == True:
        # Instance to hold level 2 packet
        level2Packet = SMANET2PlusPacket()

        # Write the payload into a level2 class structure
        level2Packet.pushRawByteArray(bluetoothbuffer.getLevel2Payload())

        if waitForPacket == True and level2Packet.getPacketCounter() != waitPacketNumber:
            print "Received packet number {0:02x} expected {1:02x}".format(level2Packet.getPacketCounter(), waitPacketNumber)
            raise Exception("Wrong Level 2 packet returned!")

        # if bluetoothbuffer.CommandCode() == 0x0008:
            # print "Level 2 packet length (according to packet): %d" % level2Packet.totalCalculatedPacketLength()

        # Loop until we have the entire packet rebuilt (may take several/hundreds of level 1 packets)
        while (bluetoothbuffer.CommandCode() != 0x0001) and (bluetoothbuffer.lastByte() != 0x7e):
            bluetoothbuffer = ReadLevel1PacketFromBluetoothStream(btSocket,mylocalBTAddress);
            level2Packet.pushRawByteArray(bluetoothbuffer.getLevel2Payload());
            v.levelone = bluetoothbuffer

        if level2Packet.isPacketFull() == False:
            raise Exception("Failed to grab all the bytes needed for a Level 2 packet")

        if level2Packet.validateChecksum(bluetoothbuffer.getLevel2Checksum()) == False:
            print level2Packet.debugViewPacket()
            raise Exception("Invalid checksum on Level 2 packet")

        v.leveltwo = level2Packet

        # Output the level2 payload (after its been combined from multiple packets if needed)
        print level2Packet.debugViewPacket()

    #print " "
    return v

def LogMessageWithByteArray(message, ba):
    """Simple output of message and bytearray data in hex for debugging"""
    print "{0}:{1}".format(message.rjust(21), ByteToHex(ba))

def ByteToHex(byteStr):
    """Convert a byte string to it's hex string representation e.g. for output."""
    return ''.join(["%02X " % x  for x in byteStr])

def BTAddressToByteArray(hexStr, sep):
    """Convert a  hex string containing seperators to a bytearray object"""
    b = bytearray()
    for i in hexStr.split(sep):
        b.append(int(i, 16))
    return b

def encodeInverterPassword(InverterPassword):
    """Encodes InverterPassword (digit number) into array for passing to SMA protocol"""
    if len(InverterPassword) > 12:
        raise Exception("Password can only be up to 12 digits in length")

    a = bytearray(InverterPassword)

    for i in xrange( 12- len(a)):
        a.append(0)

    for i in xrange(len(a)):
        if a[i] == 0:
            a[i] = 0x88
        else:
            a[i] = (a[i] + 0x88) % 0xff

    return a


def floattobytearray(value):
    # Converts a float value into 4 single bytes inside a bytearray
    # useful for converting epoch dates
    b = bytearray()
    hexStr = "{0:08x}".format(long(value))
    b.append(chr(int (hexStr[0:2], 16)))
    b.append(chr(int (hexStr[2:4], 16)))
    b.append(chr(int (hexStr[4:6], 16)))
    b.append(chr(int (hexStr[6:8], 16)))

    b.reverse()
    return b


def initaliseSMAConnection(btSocket,mylocalBTAddress,AddressFFFFFFFF,InverterCodeArray,packet_send_counter):
    print "Wait for 1st message from inverter to arrive (should be an 0002 command)"
    bluetoothbuffer = readSMABluetoothPacket(btSocket,mylocalBTAddress)
    checkPacketReply(bluetoothbuffer,0x0002);

    netid = bluetoothbuffer.levelone.getByte(4);
    print "netid=%02x" % netid
    inverterAddress = bluetoothbuffer.levelone.SourceAddress;

    LogMessageWithByteArray("inverter address", inverterAddress)

    # Reply to 0x0002 cmd with our data
    send = SMABluetoothPacket(0x1f, 0x00, 0x00, 0x02, 0x00, mylocalBTAddress, inverterAddress);
    send.pushUnescapedByteArray( bytearray([0x00, 0x04, 0x70, 0x00, netid, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]) )
    send.finish()
    print send.DisplayPacketDebugInfo("Reply to 0x02 cmd")
    send.sendPacket(btSocket);
    #pause()

    # Receive 0x000a cmd
    bluetoothbuffer = readSMABluetoothPacket(btSocket,mylocalBTAddress);
    checkPacketReply(bluetoothbuffer,0x000a);

    # Receive 0x000c cmd (sometimes this doesnt turn up!)
    bluetoothbuffer = readSMABluetoothPacket(btSocket,mylocalBTAddress);
    if bluetoothbuffer.levelone.CommandCode() != 0x0005 and bluetoothbuffer.levelone.CommandCode() != 0x000c:
        print ("Expected different command 0x0005 or 0x000c");

    # Receive 0x0005 if we didnt get it above
    if bluetoothbuffer.levelone.CommandCode() != 0x0005:
        bluetoothbuffer = readSMABluetoothPacket(btSocket,mylocalBTAddress)
        checkPacketReply(bluetoothbuffer,0x0005);


    # Now the fun begins...
    send = SMABluetoothPacket(0x3f, 0x00, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF)
    pluspacket1 = SMANET2PlusPacket(0x09, 0xa0, packet_send_counter, InverterCodeArray, 0, 0, 0)
    #0x80,
    pluspacket1.pushRawByteArray(bytearray([  0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]))
    send.pushRawByteArray(pluspacket1.getBytesForSending())
    send.finish()
    send.sendPacket(btSocket)

    bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
    checkPacketReply(bluetoothbuffer,0x0001);
    if bluetoothbuffer.leveltwo.errorCode() > 0:
        print("***** L2 Error code returned *****")

    packet_send_counter += 1;

    inverterSerial = bluetoothbuffer.leveltwo.getDestinationAddress()


def checkPacketReply(bluetoothbuffer,commandcode):
    if bluetoothbuffer.levelone.CommandCode() != commandcode:
        raise Exception("Expected command 0x{0:04x} received 0x{1:04x}".format(commandcode,bluetoothbuffer.levelone.CommandCode()))

def main(bd_addr,InverterPassword):
    #This is my fake address (5caffold)
    InverterCodeArray = bytearray([0x83,0x00,
                                   0x5c, 0xaf, 0xf0, 0x1d]);

    # Dummy arrays
    AddressFFFFFFFF = bytearray([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    Address00000000 = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    InverterPasswordArray = encodeInverterPassword(InverterPassword)
    port = 1

    packet_send_counter = 0

    try:
            print "Connecting to SMA Inverter over Bluetooth"
            btSocket = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            btSocket.connect((bd_addr, port))
            # Give BT 10 seconds to timeout so we dont hang and wait forever
            btSocket.settimeout(10)

            # http://pybluez.googlecode.com/svn/www/docs-0.7/public/bluetooth.BluetoothSocket-class.html
            mylocalBTAddress = BTAddressToByteArray(btSocket.getsockname()[0], ":")
            mylocalBTAddress.reverse()

            print "mylocalBTAddress=" + str(btSocket.getsockname()[0])

            initaliseSMAConnection(btSocket,mylocalBTAddress,AddressFFFFFFFF,InverterCodeArray,packet_send_counter);

            print "Logon to inverter"
            pluspacket1 = SMANET2PlusPacket(0x0e, 0xa0, packet_send_counter, InverterCodeArray, 0x00, 0x01, 0x01);
            pluspacket1.pushLong(0xFFFD040c)
            #0x07 = User logon, 0x0a = installer logon
            pluspacket1.pushLong(0x00000007)
            #pluspacket1.pushLong(0x00008403)
            pluspacket1.pushLong(0x00000384)
            pluspacket1.pushRawByteArray(floattobytearray(time.mktime(datetime.today().timetuple())));
            pluspacket1.pushLong(0x00000000)
            pluspacket1.pushRawByteArray(InverterPasswordArray);

            send = SMABluetoothPacket(1, 1, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF);
            send.pushRawByteArray(pluspacket1.getBytesForSending());
            send.finish();
            send.sendPacket(btSocket)

            bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
            checkPacketReply(bluetoothbuffer,0x0001);
            packet_send_counter += 1;

            if bluetoothbuffer.leveltwo.errorCode() > 0:
                    raise Exception("Error code returned from inverter - during logon - wrong password?")

            packet_send_counter += 1;


            print "Get SpotDCVoltage"
            send9 = SMABluetoothPacket(0x01, 0x01, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF)
            pluspacket9 = SMANET2PlusPacket(0x09, 0xA0, packet_send_counter, InverterCodeArray, 0x00, 0x00, 0x00)
            pluspacket9.pushLong(0x53800200)
            pluspacket9.pushLong(0x00451F00)
            pluspacket9.pushLong(0x004521FF)
            send9.pushRawByteArray(pluspacket9.getBytesForSending())
            send9.finish()
            send9.sendPacket(btSocket)

            bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
            # This will be a multi packet reply so ignore this check
            checkPacketReply(bluetoothbuffer,0x0001);

            if bluetoothbuffer.leveltwo.errorCode() > 0:
                print("***** L2 Error code returned *****")

            level2Packet=bluetoothbuffer.leveltwo
            powdata = level2Packet.getArray()


            print "Get TypeLabel"
            send9 = SMABluetoothPacket(0x01, 0x01, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF)
            pluspacket9 = SMANET2PlusPacket(0x09, 0xA0, packet_send_counter, InverterCodeArray, 0x00, 0x00, 0x00)
            pluspacket9.pushLong(0x58000200)
            pluspacket9.pushLong(0x00821E00)
            pluspacket9.pushLong(0x008220FF)
            send9.pushRawByteArray(pluspacket9.getBytesForSending())
            send9.finish()
            send9.sendPacket(btSocket)

            bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
            checkPacketReply(bluetoothbuffer,0x0001);

            if bluetoothbuffer.leveltwo.errorCode() > 0:
                print("***** L2 Error code returned *****")

            level2Packet=bluetoothbuffer.leveltwo
            powdata = level2Packet.getArray()

            packet_send_counter+=1

            print "Get Energy Production"
            send9 = SMABluetoothPacket(0x01, 0x01, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF)
            pluspacket9 = SMANET2PlusPacket(0x09, 0xA0, packet_send_counter, InverterCodeArray, 0x00, 0x00, 0x00)
            pluspacket9.pushLong(0x54000200)
            pluspacket9.pushLong(0x00260100)
            pluspacket9.pushLong(0x002622FF)
            send9.pushRawByteArray(pluspacket9.getBytesForSending())
            send9.finish()
            send9.sendPacket(btSocket)

            bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
            checkPacketReply(bluetoothbuffer,0x0001);

            if bluetoothbuffer.leveltwo.errorCode() > 0:
                print("***** L2 Error code returned *****")

            level2Packet=bluetoothbuffer.leveltwo
            powdata = level2Packet.getArray()

            packet_send_counter+=1


            print "Spot AC Voltage"
            send9 = SMABluetoothPacket(0x01, 0x01, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF)
            pluspacket9 = SMANET2PlusPacket(0x09, 0xA0, packet_send_counter, InverterCodeArray, 0x00, 0x00, 0x00)
            pluspacket9.pushLong(0x51000200)
            pluspacket9.pushLong(0x00464000)
            pluspacket9.pushLong(0x004642FF)
            send9.pushRawByteArray(pluspacket9.getBytesForSending())
            send9.finish()
            send9.sendPacket(btSocket)

            bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
            checkPacketReply(bluetoothbuffer,0x0001);

            if bluetoothbuffer.leveltwo.errorCode() > 0:
                print("***** L2 Error code returned *****")

            level2Packet=bluetoothbuffer.leveltwo
            powdata = level2Packet.getArray()

            packet_send_counter+=1


            print "SpotACTotalPower"
            send9 = SMABluetoothPacket(0x01, 0x01, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF)
            pluspacket9 = SMANET2PlusPacket(0x09, 0xA0, packet_send_counter, InverterCodeArray, 0x00, 0x00, 0x00)
            pluspacket9.pushLongs(0x51000200,0x00263F00,0x00263FFF)
            send9.pushRawByteArray(pluspacket9.getBytesForSending())
            send9.finish()
            send9.sendPacket(btSocket)

            bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
            checkPacketReply(bluetoothbuffer,0x0001);

            if bluetoothbuffer.leveltwo.errorCode() > 0:
                print("***** L2 Error code returned *****")

            level2Packet=bluetoothbuffer.leveltwo
            powdata = level2Packet.getArray()

            packet_send_counter+=1


            print "ChargeStatus"
            send9 = SMABluetoothPacket(0x01, 0x01, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF)
            pluspacket9 = SMANET2PlusPacket(0x09, 0xA0, packet_send_counter, InverterCodeArray, 0x00, 0x00, 0x00)
            pluspacket9.pushLongs(0x51000200,0x00295A00,0x00295AFF)
            send9.pushRawByteArray(pluspacket9.getBytesForSending())
            send9.finish()
            send9.sendPacket(btSocket)

            bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
            checkPacketReply(bluetoothbuffer,0x0001);

            if bluetoothbuffer.leveltwo.errorCode() > 0:
                print("***** L2 Error code returned *****")

            level2Packet=bluetoothbuffer.leveltwo
            powdata = level2Packet.getArray()

            packet_send_counter+=1



            print "SpotGridFrequency"
            send9 = SMABluetoothPacket(0x01, 0x01, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF)
            pluspacket9 = SMANET2PlusPacket(0x09, 0xA0, packet_send_counter, InverterCodeArray, 0x00, 0x00, 0x00)
            pluspacket9.pushLongs(0x51000200,0x00465700,0x004657FF)
            send9.pushRawByteArray(pluspacket9.getBytesForSending())
            send9.finish()
            send9.sendPacket(btSocket)

            bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
            checkPacketReply(bluetoothbuffer,0x0001);

            if bluetoothbuffer.leveltwo.errorCode() > 0:
                print("***** L2 Error code returned *****")

            level2Packet=bluetoothbuffer.leveltwo
            powdata = level2Packet.getArray()

            packet_send_counter+=1

            print "OperationTime"
            send9 = SMABluetoothPacket(0x01, 0x01, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF)
            pluspacket9 = SMANET2PlusPacket(0x09, 0xA0, packet_send_counter, InverterCodeArray, 0x00, 0x00, 0x00)
            pluspacket9.pushLongs(0x54000200, 0x00462E00, 0x00462FFF)
            send9.pushRawByteArray(pluspacket9.getBytesForSending())
            send9.finish()
            send9.sendPacket(btSocket)

            bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
            checkPacketReply(bluetoothbuffer,0x0001);

            if bluetoothbuffer.leveltwo.errorCode() > 0:
                print("***** L2 Error code returned *****")

            level2Packet=bluetoothbuffer.leveltwo
            powdata = level2Packet.getArray()

            packet_send_counter+=1

            print "Inverter Temperature"
            send9 = SMABluetoothPacket(0x01, 0x01, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF)
            pluspacket9 = SMANET2PlusPacket(0x09, 0xA0, packet_send_counter, InverterCodeArray, 0x00, 0x00, 0x00)
            pluspacket9.pushLongs(0x52000200, 0x00237700, 0x002377FF)
            send9.pushRawByteArray(pluspacket9.getBytesForSending())
            send9.finish()
            send9.sendPacket(btSocket)

            bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
            checkPacketReply(bluetoothbuffer,0x0001);

            if bluetoothbuffer.leveltwo.errorCode() > 0:
                print("***** L2 Error code returned *****")

            level2Packet=bluetoothbuffer.leveltwo
            powdata = level2Packet.getArray()

            packet_send_counter+=1

            print "DeviceStatus"
            send9 = SMABluetoothPacket(0x01, 0x01, 0x00, 0x01, 0x00, mylocalBTAddress, AddressFFFFFFFF)
            pluspacket9 = SMANET2PlusPacket(0x09, 0xA0, packet_send_counter, InverterCodeArray, 0x00, 0x00, 0x00)
            pluspacket9.pushLongs(0x51800200, 0x00214800, 0x002148FF)
            send9.pushRawByteArray(pluspacket9.getBytesForSending())
            send9.finish()
            send9.sendPacket(btSocket)

            bluetoothbuffer = readSMABluetoothPacket(btSocket, packet_send_counter, True,mylocalBTAddress)
            checkPacketReply(bluetoothbuffer,0x0001);

            if bluetoothbuffer.leveltwo.errorCode() > 0:
                print("***** L2 Error code returned *****")

            level2Packet=bluetoothbuffer.leveltwo
            powdata = level2Packet.getArray()

            packet_send_counter+=1

            #Make sure the packet counter wont exceed 4096
            if packet_send_counter>=0x0FFF:
                    packet_send_counter=0


    except bluetooth.btcommon.BluetoothError as inst:
            print >>sys.stderr, "Bluetooth Error"
            print >>sys.stderr, type(inst)     # the exception instance
            print >>sys.stderr, inst.args      # arguments stored in .args
            print >>sys.stderr, inst           # __str__ allows args to printed directly
            traceback.print_exc(file=sys.stderr)

            btSocket.close()


    except Exception as inst:
            print >>sys.stderr, type(inst)     # the exception instance
            print >>sys.stderr, inst.args      # arguments stored in .args
            print >>sys.stderr, inst           # __str__ allows args to printed directly
            traceback.print_exc(file=sys.stderr)

            btSocket.close()

parser = argparse.ArgumentParser(description='Report statistics from SMA PV inverter.', epilog='Copyright 2013-2017 Stuart Pittaway.')

parser.add_argument('addr', metavar='addr',  type=str, help='Bluetooth address of SMA inverter in 00:80:22:11:cc:55 format, run hcitool scan to find yours')
parser.add_argument('passcode', metavar='passcode',  type=str, help='NUMERIC pass code for the inverter, default of 0000')

args = parser.parse_args()

main(args.addr,args.passcode)

exit()

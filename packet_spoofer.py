#################################
# author@ Daniel Laden          #
# email@ dthomasladen@gmail.com #
# author@ Josh Cullings         #
# email@ cullingsjosh@gmail.com #
#################################

from scapy.all import *
import sys
import socket
import hashlib
import random

#192.0.0.0
#|network|.|network|.|subnet|.|host|
#|unchanged|.|unchanged|.|0-9 set codes 10-255 information|.|0-255 information|
# handshakes for RSA
# handshakes for DH
# normal flag for RSA
# normal flag for DH
# exponential flag for RSA
# exponential flag for DH
# sys.argv[1] set ip

import random
import cryptography
from cryptography.fernet import Fernet
import base64
import random
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class diffehelm:  #Alice: send in (a, g, p) where a = Bob's secret rand num
                                                 #g = random num
                                                 #p = prime

    def __init__(self,a = random.randint(1,100), g = random.randint(1,100), p = 0):
        def isprime(a):
            count = 0
            for i in range(2, a // 2 + 1):
                if a % i == 0:
                    count = count + 1
            if count <= 0:
                return True
            else:
                return False

        self.a = a
        self.g = g
        self.B = 0
        self.iv = os.urandom(16)

        if p is 0:
            self.primes = [i for i in range(2,10000) if isprime(i)]
            self.p=random.choice(self.primes)
        else:
            self.p=p;


        self.A = (self.g**self.a) % self.p    ##Algorithm to generate A to send to Bob
        print("Alice's secret number(a): %d" %self.a)
        print("Shared randomly generated int value: %d" %self.g)
        print("Shared Prime: %d" %self.p)




    def getSwapValue(self, a, g, p):
        print("Bob's secret number(a): %d" %a)
        print("Shared randomly generated int value %d" %g)
        print("Shared Prime: %d" %p)
        B = (g**a) % p    ##Algorithm to generate A or B to send to Bob X Alice
        print("B: ", end = "")

        return B

    def getA(self):
        return self.A

    def getg(self):
        return self.g


    def getp(self):
        return self.p

    def setB(self,B):
        self.B = B;


    def DH_encrypt(self, message):            #Encrypt Method
        encryptedMessage = "as"

        if self.B is 0:
            print("You must set B")

        else:
            key = self.B ** self.a % self.p
            print("------------------------------------")
            print("Key: ", end = "")
            print(key)

            messageEnc = message.encode('utf-8')

            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=None,
                backend=default_backend()).derive(str(key).encode('utf-8'))
            backend = default_backend()
            AESkey = derived_key
            cipher = Cipher(algorithms.AES(AESkey), modes.CBC(self.iv), backend=backend)
            encryptor = cipher.encryptor()
            encryptedMessage = encryptor.update(messageEnc) + encryptor.finalize()
            print("Encrypted Message: ", end = "")
            print(encryptedMessage)

        return encryptedMessage


    def DH_decrypt(self, messageToDecrypt):          #Decrypt Method

        key = self.B ** self.a % self.p

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
            backend=default_backend()).derive(str(key).encode('utf-8'))
        backend = default_backend()
        AESkey = derived_key
        deCipher = Cipher(algorithms.AES(AESkey), modes.CBC(self.iv), backend=backend)
        decryptor = deCipher.decryptor()
        finalMessage = decryptor.update(messageToDecrypt) + decryptor.finalize()

        return finalMessage

# Code from reference (1)
def lcm(x, y):
   """This function takes two
   integers and returns the L.C.M."""

   # choose the greater number
   if x > y:
       greater = x
   else:
       greater = y

   while(True):
       if((greater % x == 0) and (greater % y == 0)):
           lcm = greater
           break
       greater += 1

   return lcm

# This method is from reference (2)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# This method is from reference (2)
def coprime(a, b):
    return gcd(a, b) == 1

def RSA_decrypt(c, p, q):
    n = p*q
    upper = lcm(p-1,q-1)
    e=17
    i=5
    while(e==0):
        if (coprime(i,upper)):
            e=i
        i+=2
    i=1
    d=0
    while(d==0 and i<upper):
        if (((i*e)%upper) == 1):
            d=i
        i+=1
    m=(c**d)%n
    #print('Decrypted Message: %d' % m)
    return m

def RSA_encrypt(m, p, q):
    n = p*q
    upper = lcm(p-1,q-1)
    e=17
    i=5
    while(e==0):
        if (coprime(i,upper)):
            e=i
        i+=2
    i=1
    d=0
    while(d==0 and i<upper):
        if (((i*e)%upper) == 1):
            d=i
        i+=1
    c=(m**e)%n
    #print('Original Message: %d\nEncrypted Message %d' % (m,c))
    return c


userIP=sys.argv[1]
destIP="127.0.0.1"
sourcePort=15000
destPort=15001


message = b"I stole the Sweet Feet shoes, the cops are coming, meet me at Montes"


#encryped based on sys.argv[2]
if(sys.argv[2] == "RSA"):
    #RSA encryption
    print(message)
    p = int(sys.argv[3])
    q = int(sys.argv[4])

    new_message = ""
    for e in message:
        m = RSA_encrypt(e, p, q)
        new_message=new_message+" "+str(m)
        # d = RSA_decrypt(m, 17, 223)
        # print(str(m)+"----"+str(d)+"----"+chr(d))

    #handshake IP
    split = userIP.split(".")
    split[2]="1"
    split[3]=str(random.randint(0,255))

    handshake=split[0]
    for sp in split[1:]:
        handshake=handshake+"."+sp

    #setting IP
    split = userIP.split(".")
    split[2]="3"
    split[3]=str(random.randint(0,255))

    setting=split[0]
    for sp in split[1:]:
        setting=setting+"."+sp

    #message IP
    split = userIP.split(".")
    split[2]=str(p)
    split[3]=str(q)

    messageIP=split[0]
    for sp in split[1:]:
        messageIP=messageIP+"."+sp

elif(sys.argv[2] == "DH"):
    #RSA encryption
    print(message)
    p = int(sys.argv[3]) #limit to # 6 digits 2
    g = int(sys.argv[4]) #limit to # 6 digits 2

    a = int(sys.argv[5])
    b = int(sys.argv[6])

    newer_diffehelm = diffehelm(a, g, p)              #(a, g, p) to get A
    newer_diffehelm.setB(b)

    new_message = newer_diffehelm.DH_encrypt("I stole some shoes. The police are after me.....")


    #handshake IP
    split = userIP.split(".")
    split[2]="2"
    split[3]=str(random.randint(0,255))

    handshake=split[0]
    for sp in split[1:]:
        handshake=handshake+"."+sp

    #setting p IP
    split = userIP.split(".")
    split[2]="4"
    split[3]=str(random.randint(0,255))

    setting=split[0]
    for sp in split[1:]:
        setting=setting+"."+sp

    #p packet
    split = userIP.split(".")
    p = str(p)
    split[2]=p[:2]
    split[3]=p[2:]

    ppacket=split[0]
    for sp in split[1:]:
        ppacket=ppacket+"."+sp


    #setting g IP
    split = userIP.split(".")
    split[2]="6"
    split[3]=str(random.randint(0,255))

    setting2=split[0]
    for sp in split[1:]:
        setting2=setting2+"."+sp

    #p packet
    split = userIP.split(".")
    g = str(g)
    split[2]=g[:3]
    split[3]=g[3:]

    gpacket=split[0]
    for sp in split[1:]:
        gpacket=gpacket+"."+sp

    #message IP
    split = userIP.split(".")
    split[2]=str(a)
    split[3]=str(b)

    messageIP=split[0]
    for sp in split[1:]:
        messageIP=messageIP+"."+sp

print(new_message)


#Send the handshake (RSA or DH)
junk = ("dephosphorylated"+str(random.randint(0,100000))).encode()
print(junk)

junk = hashlib.sha256(junk).hexdigest().encode()
print(junk)

spoofed_handshake = IP(src=handshake, dst=destIP) / TCP(sport=sourcePort, dport=destPort) / junk

send(spoofed_handshake)

#Send the setting (normal or Exponential)
junk = ("dephosphorylated"+str(random.randint(0,100000))).encode()
print(junk)

junk = hashlib.sha256(junk).hexdigest().encode()
print(junk)

spoofed_setting = IP(src=setting, dst=destIP) / TCP(sport=sourcePort, dport=destPort) / junk

send(spoofed_setting)

try:
    #Send the setting (normal or Exponential)
    junk = ("dephosphorylated"+str(random.randint(0,100000))).encode()
    print(junk)

    junk = hashlib.sha256(junk).hexdigest().encode()
    print(junk)

    spoofed_setting = IP(src=ppacket, dst=destIP) / TCP(sport=sourcePort, dport=destPort) / junk

    send(spoofed_setting)

    junk = ("dephosphorylated"+str(random.randint(0,100000))).encode()
    print(junk)

    junk = hashlib.sha256(junk).hexdigest().encode()
    print(junk)

    spoofed_setting = IP(src=setting2, dst=destIP) / TCP(sport=sourcePort, dport=destPort) / junk

    send(spoofed_setting)

    #Send the setting (normal or Exponential)
    junk = ("dephosphorylated"+str(random.randint(0,100000))).encode()
    print(junk)

    junk = hashlib.sha256(junk).hexdigest().encode()
    print(junk)

    spoofed_setting = IP(src=gpacket, dst=destIP) / TCP(sport=sourcePort, dport=destPort) / junk

    send(spoofed_setting)

except:
    print("Not a DH additional settings not needed")

#Send the information packet

actual_message = IP(src=messageIP, dst=destIP) / TCP(sport=sourcePort, dport=destPort) / new_message

send(actual_message)








#########################################################
#Coding resources
#
#https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
#https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
#https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
# (1) https://www.programiz.com/python-programming/examples/lcm
# (2) https://stackoverflow.com/questions/39678984/efficient-check-if-two-numbers-are-co-primes-relatively-primes
#https://stackoverflow.com/questions/38956401/ip-spoofing-in-python-3
# https://docs.python.org/3/library/random.html
# https://stackoverflow.com/questions/44304988/permissionerror-errno-1-operation-not-permitted
# https://docs.python.org/3/library/hashlib.html
#########################################################

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

def decrypt(c, p, q):
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

def encrypt(m, p, q):
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
p = int(sys.argv[3])
q = int(sys.argv[4])

message = b"I stole the Sweet Feet shoes, the cops are coming, meet me at Montes"


#encryped based on sys.argv[2]
if(sys.argv[2] == "RSA"):
    #RSA encryption
    print(message)

    new_message = ""
    for e in message:
        m = encrypt(e, p, q)
        new_message=new_message+" "+str(m)
        # d = decrypt(m, 17, 223)
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
    #DH encryption
    message = encode(message)
    print(message)

    for e in message:
        print(encrypt(e, 17, 223))

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

#Send the information packet

actual_message = IP(src=messageIP, dst=destIP) / TCP(sport=sourcePort, dport=destPort) / new_message

send(actual_message)








#########################################################
#Coding resources
#
# (1) https://www.programiz.com/python-programming/examples/lcm
# (2) https://stackoverflow.com/questions/39678984/efficient-check-if-two-numbers-are-co-primes-relatively-primes
#https://stackoverflow.com/questions/38956401/ip-spoofing-in-python-3
# https://docs.python.org/3/library/random.html
# https://stackoverflow.com/questions/44304988/permissionerror-errno-1-operation-not-permitted
# https://docs.python.org/3/library/hashlib.html
#########################################################

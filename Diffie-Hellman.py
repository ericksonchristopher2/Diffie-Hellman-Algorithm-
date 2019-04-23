###################################
# Author(s): Christopher Erickson #
#            Daniel Laden         #
#            Josh Cullings        #
# Date: 4/22/2019                 #
###################################
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


    def encrypt(self, message):            #Encrypt Method
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


    def decrypt(self, messageToDecrypt):          #Decrypt Method

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



if __name__ == '__main__':
    #new_diffehelm = diffehelm()
    #new_diffehelm.encrypt("I stole some shoes. The police are after me. I need a place to stay!")
    #print(new_diffehelm.primes)
    #print(new_diffehelm.p)
    #print(new_diffehelm.g)
    #newer_diffehelm.encrypt("I stole some shoes. The police are after me. I need a place to stay!")
    #print(newer_diffehelm.p)
    #print(newer_diffehelm.g)

    newer_diffehelm = diffehelm(654321, 420013, 2609)              #(a, g, p) to get A
    newer_diffehelm.setB(14)
    print("A: ", end = "")
    print(newer_diffehelm.A)
    print(newer_diffehelm.getSwapValue(12345, 420013, 2609))      #(a, g, p) to get B 
    encryptedMessage = newer_diffehelm.encrypt("I stole some shoes. The police are after me.....")
    print("Decrypted Message: ", end = "")
    print(newer_diffehelm.decrypt(encryptedMessage))
    
    
################################################################################
#                               Citations                                      #
#https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange             #
#https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/     #
#https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/ #
################################################################################

    

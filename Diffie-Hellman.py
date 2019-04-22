import random
import cryptography
from cryptography.fernet import Fernet
import base64

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
        
        if p is 0:
            self.primes = [i for i in range(2,10000) if isprime(i)]
            self.p=random.choice(self.primes)
        else:
            self.p=p;

        self.A = (self.g**self.a) % self.p    ##Algorithm to generate A to send to Bob

    def getSwapValue(self, a, g, p):

        return (g**a) % p    ##Algorithm to generate A or B to send to Bob X Alice
        


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
            f = Fernet(base64.urlsafe_b64encode(bytes(key)))
            encryptedMessage = f.encrypt(message)
        
        return encryptedMessage


    def decrypt():                         #Decrypt Method
        print("otherstuff")






if __name__ == '__main__':
    #new_diffehelm = diffehelm()
    #new_diffehelm.encrypt("I stole some shoes. The police are after me. I need a place to stay!")
    #print(new_diffehelm.primes)
    #print(new_diffehelm.p)
    #print(new_diffehelm.g)

    newer_diffehelm = diffehelm(4, 42, 1001)
    newer_diffehelm.setB(14)
    print(newer_diffehelm.A)
    print(newer_diffehelm.getSwapValue(3, 42, 1001))
    print(newer_diffehelm.encrypt("I stole some shoes. The police are after me. I need a place to stay!"))
    #newer_diffehelm.encrypt("I stole some shoes. The police are after me. I need a place to stay!")
    #print(newer_diffehelm.p)
    #print(newer_diffehelm.g)

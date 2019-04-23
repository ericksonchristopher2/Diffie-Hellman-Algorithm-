###################################
# Author(s): Josh Cullings        #
#            Daniel Laden         #
#            Christopher Erickson #
# Date: 4/22/2019                 #
###################################
    
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
    
p=61
q=53

c=encrypt(65,p,q)
m=decrypt(c,p,q)

###################################################################################################################
# References:                                                                                                     #
# (1) https://www.programiz.com/python-programming/examples/lcm                                                   #
# (2) https://stackoverflow.com/questions/39678984/efficient-check-if-two-numbers-are-co-primes-relatively-primes #
###################################################################################################################

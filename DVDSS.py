#Delay Verification Signature Scheme
#Use Python 3.8 or higher

import math
import time
import random
from Crypto.Util import number


#Signer DS_Setup - Setup the Modulus a Blum Integer
def DS_Setup(x, bits, t):
	def genPrime(bits):
		potential_prime = 1
		while potential_prime % 4 == 1:
			potential_prime = number.getPrime(bits)
		return potential_prime

	x = 0
	while x <1: 
		p = genPrime(bits)
		q = genPrime(bits)
		if p != q and q % 4 != 1:
			N = p * q
			pp = N
		x += 1
	
	td = (p-1) * (q-1) #td = phiN
	
	return pp, td

#Signer DS_Gen - Generate secret signing key and Challenge
def DS_Gen(pp, td, t):
	N = pp
	phiN = td
	
	gcd = 0
	while gcd != 1:
		x = random.randint(2, N//2)
		x_0 = pow(x, 2, N)
		
		pk = pow(x_0, pow(2, t-1, phiN), N) #square root of x_t - public verification key, will be recovered by Extract
		gcd = math.gcd(pk, phiN)
	

	x_t = pow(pk, 2, N)
	sk = pow(pk, -1, phiN) #EEA to derive secret key - multiplicative inverse of pk
	C = (x_0, x_t)
	return sk, C, t

#Signer DS_Sign - Sign the message
def DS_Sign(m, sk, pp): 
	N = pp
	s = pow(m, sk, N) #Just use textbook RSA for now
	return m, s

#Verifier DS_Extract - Extract time-locked verification public key
def DS_Extract(pp, C, t): 
	N = pp
	x_0 = C[0]
	
	pk = pow(x_0, pow(2, t-1), N) #cannot reduce exponent by td = phiN because no knowledge of p,q	
	return pk

#Verifier DS_Verify - Verify signature s, to recover m
def DS_Verify(m, s, pk, pp):
	N = pp
	V = 'reject'
	
	m_prime = pow(s, pk, N)
	
	if m == m_prime:
		V = 'accept'
		return V
	else:
		return V




# run functions
z = 0
bits = 1024
t = 100000 #increase for larger time delay

m = 8 #hardcode integer for now

while z < 1: 
	start_time = time.time()
	print('\nDS_Setup running...')
	pp, td = DS_Setup(1, bits ,t)
	print(
		'pp:', pp, 
		 '\ntd:', td
		)
	print('DS_Setup time:' , round(time.time() - start_time , 4), 'seconds')
	
	start_time = time.time()
	print('\nDS_Gen running...')
	sk, C, t = DS_Gen(pp, td, t)
	print(
		'sk:', sk, 
		'\nC:', C, 
		'\nt:', t 
		)
	print('DS_Gen time:' , round(time.time() - start_time , 4), 'seconds')	
	
	start_time = time.time()
	print('\nDS_Sign running...')
	m, s = DS_Sign(m, sk, pp)
	print(
		'm:', m,
		'\ns:', s
		)
	print('DS_Sign time:' , round(time.time() - start_time , 4), 'seconds')
	
	
	start_time = time.time()
	print('\nDS_Extract running...')
	pk = DS_Extract(pp, C, t)
	print(
		'pk:', pk
		)
	print('DS_Extract time:' , round(time.time() - start_time , 4), 'seconds')			


	start_time = time.time()
	print('\nDS_Verify running...')
	V = DS_Verify(m, s, pk, pp)
	print(
		'V:', V
		)
	print('DS_Verify time:' , round(time.time() - start_time , 4), 'seconds')		
	
	z += 1
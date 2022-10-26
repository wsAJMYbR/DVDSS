#Delay Verification Signature Scheme for nCk Selection Scheme
#Use Python 3.8 or higher

import math
import time
import random
from Crypto.Util import number


#Signer DV_Setup - Setup the Modulus a Blum Integer
def DV_Setup(x, bits, t):
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

#Signer DV_Gen - Generate secret signing key and Challenge
def DV_Gen(pp, td, t):
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

#Signer DV_Sign - Sign the message
def DV_Sign(m, sk, pp): #Just use textbook RSA for now
	N = pp
	s = pow(m, sk, N)
	return m, s

#Signer Sign_nCk - select x of M items, then Sign each element and output random for the other elements
def Sign_nCk(x, sk, pp):
	
	#Create message space M
	def Create_M(a,b): #use integers
		if a < b: 
			M = list(range(a,b))
			return M
		else:
			print('a !< b, exiting...')
			exit()
	
	#Select x elements from M
	def Select_nCk(x, M):
		if x < len(M):
			nCk = random.sample(M, x)
			return nCk
		else:
			print('x > len(M), exiting...')
			exit()			
	
	#Sign only the nCk elements
	def Sign_nCk(M, nCk, sk, pp):
		N = pp
		S = []
		for m in M:
			if m in nCk: 
				m, s = DV_Sign(m, sk, pp)
				S.append(s)
			else: 
				s = random.randint(2,N)
				S.append(s)
		return S
				
	M = Create_M(a,b)		
	nCk = Select_nCk(x, M)
	S = Sign_nCk(M, nCk, sk, pp)
	
	return M, nCk, S #only outputing M and nCk to print to screen
	
#Verifier DV_Extract - Extract time-locked verification public key
def DV_Extract(pp, C, t): #Change Latex to DV_Extract
	N = pp
	x_0 = C[0]
	x_t = C[1]
	
	pk = pow(x_0, pow(2, t-1), N) #cannot reduce exponent by td = phiN because no knowledge of p,q	
	
	if pow(pk, 2, N) == x_t:
		pk = pk
	else:
		print('not sound exiting...')
		exit()
	
	return pk

#Verifier DV_Verify - Verify signature s, to recover m
def DV_Verify(m, s, pk, pp):
	N = pp
	v = 'reject'
	
	m_prime = pow(s, pk, N)
	
	if m == m_prime:
		v = 'accept'
		return v
	else:
		return v

#Verifier Verify_nCk - verify which of the x of M items was actually signed
def Verify_nCk(M, S, pk, pp):
	N = pp
	
	V = []	
	i = 0
	while i < len(M):
		v = DV_Verify(M[i], S[i], pk, pp)
		if v == 'accept':
			V.append(M[i])
		else:
			V.append('bot')
		i += 1
	return V
	
	i = 0 #just for observation
	nCk_prime = []
	while i < len(M):
		if M[i] == V[i]:
			nCk_prime.append(V[i])
		i += 1
	print('nCk_prime:', nCk_prime)	
	


# run functions
#how many iterations to run
z = 0

#size of primes and time parameter
bits = 1024
t = 1000000

#size of message space and sample of message space
a = 1
b = 60
x = 6


while z < 1: 
	start_time = time.time()
	print('\nDV_Setup running...')
	pp, td = DV_Setup(1, bits ,t)
	print(
		'pp:', pp, 
		 '\ntd:', td
		)
	print('DV_Setup time:' , round(time.time() - start_time , 4), 'seconds')
	#input('Press Enter to run DV_Gen...')
	
	start_time = time.time()
	print('\nDV_Gen running...')
	sk, C, t = DV_Gen(pp, td, t)
	print(
		'sk:', sk, 
		'\nC:', C, 
		'\nt:', t 
		)
	print('DV_Gen time:' , round(time.time() - start_time , 4), 'seconds')	
	#input('Press Enter to run Sign_nCk...')

	start_time = time.time()
	print('\nSign_nCk running...')
	M, nCk, S = Sign_nCk(x, sk, pp)
	print(
		'M:', M,
		'\nnCk:', nCk ,
		'\nS:', S
		)
	print('Sign_nCk time:' , round(time.time() - start_time , 4), 'seconds')
	#input('Press Enter to run DV_Extract..')
		
	
	start_time = time.time()
	print('\nDV_Extract running...')
	pk = DV_Extract(pp, C, t)
	print(
		'pk:', pk
		)
	print('DV_Extract time:' , round(time.time() - start_time , 4), 'seconds')	
	#input('Press Enter to run Verify_nCk...')

	start_time = time.time()
	print('\nVerify_nCk running...')
	V = Verify_nCk(M, S, pk, pp)
	print(
		'V', V
		)
	print('Verify_nCk time:' , round(time.time() - start_time , 4), 'seconds')			

	z += 1
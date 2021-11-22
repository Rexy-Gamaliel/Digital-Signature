import os
import random
import time
import logging
from math import ceil

class PrimeGenerator():
    '''
        Generate n-bit prime number by doing:
        1. Generate n-bit random odd number (at least 2**(n-1))
        2. Sieve of Eratosthenes: check if the number is not prime by dividing it by small prime numbers
        3. Rabin-Miller Primality test: check with high probability if the number is prime
        PrimeGenerator can be initialized with a number of bits of the prime number to be generated
    '''
    def __init__(self, n_bits=None):
        self.debug = False
        if n_bits is None:
            self.n_bits = 128
        else:
            self.n_bits = n_bits
        self.timestamp = time.perf_counter()
        self.small_primes = self.generate_small_primes()

        if self.debug:
            level = logging.DEBUG
            fmt = '[%(levelname)s] %(asctime)s - %(message)s'
            logging.basicConfig(level=level, format=fmt)

    def generate_small_primes(self, limit:int=None):
        if limit is None:
            limit = 1000
        isprime = [True] * limit

        for i in range(2, limit):
            if not isprime[i]:
                continue
            for j in range(i+1, limit):
                if j % i == 0:
                    isprime[j] = False
        
        return [i for (i, _) in filter(lambda x: x[1], enumerate(isprime))][2:]
    
    def sieve_of_erathosthenes_test(self, number: int):
        '''
            Check if number is not prime by dividing it with small primes
            Return True if number pass this test (is not divisible by any small prime numbers)
            return False otherwise
        '''
        for prime in self.small_primes:
            if number % prime == 0:
                return False
        return True
    
    def random_n_bits(self, n: int=64):
        '''
        Generate n bits odd number in range(2**(n-1)+1, 2**n, 2)
        '''
        return random.randrange((1<<(n-1)) + 1, 1<<(n), 2)
    
    
    # [ DELETE LATER ]
    # From wikipedia: https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
    # Input #1: n > 3, an odd integer to be tested for primality
    # Input #2: k, the number of rounds of testing to perform
    # Output: “composite” if n is found to be composite, “probably prime” otherwise

    # write n as 2**r·d + 1 with d odd (by factoring out powers of 2 from n − 1)
    # WitnessLoop: repeat k times:
    #     pick a random integer a in the range [2, n − 2]
    #     x ← a**d mod n
    #     if x = 1 or x = n − 1 then
    #         continue WitnessLoop
    #     repeat r − 1 times:
    #         x ← x**2 mod n
    #         if x = n − 1 then
    #             continue WitnessLoop
    #     return “composite”
    # return “probably prime”
    def miller_rabin_test(self, n, k: int = 20):
        '''
            [DESC]
                Perform Miller-Rabin test to determine with high probability if n is prime
            [PARAMS]
                n: int { number to be tested }
                k: int { number of iteration, default=20 }
            [RETURN]
                True if n passes Miller-Rabin test in k iteration.
                False otherwise
        '''
        # Write n as 2**r . d + 1, where d is odd, by factorizing powers of 2 from n-1
        d = n - 1
        r = 0
        while d % 2 == 0:
            d //= 2
            r += 1
        # d is odd, n-1 = 2**r . d
        # print(f'{n = } = 2**r . d + 1, {d = }, {r = }')

        for _ in range(k):
            a = random.randrange(2, n-1)
            # x ← a**d mod n
            x = pow(a, d, n)
            # print(f'{a = } = rand[2, n-2], {x = } = (a**d) % n')
            if x == 1 or x == n-1:
                continue
            
            for _ in range(r-1):
                # x ← x**2 mod n
                x = pow(x, 2, n)
                if x == n-1:
                    continue
            
            return False
        return True

    def generate_prime(self):
        if self.debug:
            logging.info('start: ', time.perf_counter()-self.timestamp)
            self.timestamp = time.perf_counter()
        
        while True:
            number = self.random_n_bits(self.n_bits)

            if not self.sieve_of_erathosthenes_test(number):
                # The number does not pass this test
                continue

            if not self.miller_rabin_test(number):
                # The number does not pass this test
                continue

            if self.debug:
                print('end: ', time() - self.timestamp)
            
            return number

dirname = os.path.dirname(__file__)
# print("awal:", dirname)
# dirname = os.path.dirname(os.path.dirname(dirname))
# dirname = os.path.dirname(dirname)
# print("akhir:", dirname)

def readfile(directory):
    # !file directory is relative to project folder (public-key-cipher)!
    filename = os.path.join(dirname, directory)
    with open(filename, 'rb') as file:
        bytes = file.read()
        return bytes

def writefile(directory, content):
    # !file directory is relative to project folder (public-key-cipher)!
    filename = os.path.join(dirname, directory)
    with open(filename, 'wb') as file:
        file.write(content)

def readtxt(directory):
    # !file directory is relative to project folder (public-key-cipher)!
    filename = os.path.join(dirname, directory)
    # print(filename)
    with open(filename, 'r') as file:
        return file.readlines()

def writetxt(directory, content):
    # !file directory is relative to project folder (public-key-cipher)!
    filename = os.path.join(dirname, directory)
    with open(filename, 'w') as file:
        file.write(content)

def byte2int(b: bytes):
    return int.from_bytes(b, byteorder='little')

def int2byte(i: int):
    # import math
    length = i.bit_length() // 8
    return i.to_bytes(length, byteorder='little')

""" For testing purpose """
def hex2byte(inp):
    '''
        Hex string to bytes
        e.g.: 'ab' -> b'\xab'
              'abcd' -> b'\xab\xcd'
              'abc' -> b'\x0a\xbc'
    '''
    # r = b''
    # n_hex = len(inp)
    # if n_hex % 2 == 0:
    #     for i in range(n_hex//2)[::-1]:
    #         int_val = int(inp[i-1], 16) * 16 + int(inp[i], 16)
    #         byte_val = int.to_bytes(int_val, 1, 'big')
    # i = n_hex - 1
    # while i > 0:
    #     val = int(inp[i], 16)
    #     r = int.to_bytes(, 1, 'big') + r
    # return r
    return int.to_bytes(int(inp, 16), ceil(len(inp)/2), 'big')

""" For testing purpose """
def byte2hex(inp):
    '''
        Bytes
        e.g.: b'\xab' -> 'ab'
              b'\xab\xcd' -> 'abcd'
              b'\x0a\xbc' -> 'abc'
    '''
    # r = ''
    # for b in inp:
    #     b_int = b
    #     r += hex(b_int//16)[2] + hex(b_int%16)[2]
    # return r
    return hex(int.from_bytes(inp, 'big'))[2:]

# def byte2int(data):
#     output = 0
#     size = len(data)
#     for index in range(size):
#         output |= data[index] << (8 * (size - 1 - index))
#     return output

# def int2byte(integer, _bytes):
#     output = bytearray()
#     for byte in range(_bytes):        
#         output.append((integer >> (8 * (_bytes - 1 - byte))) & 255)
#     return output

def gcd(a, b):
    # Return FPB/GCD of a and b
    if a > b:
        nmax = a
        nmin = b
    else:
        nmax = b
        nmin = a
    #
    while True:
        # while nmax >= nmin:
        #     nmax -= nmin
        nmax %= nmin
        nmax, nmin = nmin, nmax
        if nmin == 0:
            break
        # nmax > nmin, nmin != 0
    return nmax

def isqrt(n):
    # Determine if n is a perfect square with Newton's method
    # Return True if n is a perfect square
    # n > 0
    x = n//2
    seen = set([x])
    while x**2 != n:
        x = (x + (n//x)) // 2
        if x in seen: return False
        seen.add(x)
    return True

def legendre_symbol(a, p):
    """
        [DESC]
            Determine Legendre symbol a|p = a^((p-1)/2) (mod p)
            The Legendre symbol is used to determine if there is a perfect square that is equivalent
            to a in modulo p (aka a has a square root modulo on p),
            i.e. there's x in range [0, p) such that x^2 (mod p) = a
        [PARAMS]
            p: int      { integer, prime }
            a: int      { integer in range [0,p), relatively prime to p }
        [RETURN]
            1 if a has a square root modulo
            -1 if a doesn't have a square root modulo
            0 if a is divisible by p
    """
    ls = pow(a, (p-1)//2, p)
    return -1 if ls == p-1 else ls

def modular_sqrt(a, p):
    """
        [DESC]
            Tonelli-Shanks algorithm to solve the congruence:
            x^2 = a (mod p)

        Find a quadratic residue (mod p) of 'a'. p
        must be an odd prime.
        Solve the congruence of the form:
            x^2 = a (mod p)
        And returns x. Note that p - x is also a root.
        0 is returned is no square root exists for
        these a and p.
    """
    # Simple cases
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p+1)//4, p)

    # Factorize powers of 2 from p-1
    # i.e. express p-1 in the form of s*(2^e), where s is odd
    s = p-1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    # Find some 'n' with a Legendre symbol n|p = -1.
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    # x is the square root module that we want to solve, x's value gets better for each iteration.
    # b is the "fudge factor" - by how much we're off with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update both a and b
    # r is the exponent that decreases with each update
    # p = s * 2^e + 1
    x = pow(a, (s + 1)//2, p)   # x = a^(s+1)/2 mod p
    b = pow(a, s, p)            # b = a^s mod p; x^2 = ab mod p = a^(s+1) mod p
    g = pow(n, s, p)            # g = n^s mod p
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2**(r-m-1), p)
        g = pow(gs, 2,  p)
        x = (x * gs) % p
        b = (b * g) % p
        r = m

def test_util():
    pg = PrimeGenerator()
    print(pg.generate_prime())
    print(pg.generate_prime())
    pass

if __name__ == "__main__":
    test_util()
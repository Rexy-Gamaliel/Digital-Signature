# import sys
# sys.path.append("../../../public-key-cipher")
# from math import floor
import utility as util
import logging
import time
import os
from random import randrange
from collections import defaultdict
from constant import CONFIG_DIR, TEST_DIR, ECC_PRIME_BIT, ECC_COEF_BIT

### DOING k randomly ###

def setup_logger():
    logger = logging.getLogger(__name__)
    file = logging.FileHandler("ecc.log")
    file.setLevel(logging.INFO)
    fileformat = logging.Formatter('[%(levelname)s] %(asctime)s - %(message)s')
    file.setFormatter(fileformat)
    logger.addHandler(file)

INFPOINT = (None, None)

class ECC():
    def __init__(self):
        self.debug = True      # Change to True to show log
        # self._private_file = f"{CONFIG_DIR}/ecc-private.txt"
        # self._public_file = f"{CONFIG_DIR}/ecc-public.txt"
        # self._config_file = f"{CONFIG_DIR}/ecc-config.txt"
        # self._test_input = f"{TEST_DIR}/ecc-input.txt"
        # self._test_encrypted = f"{TEST_DIR}/ecc-encrypted.txt"
        # self._test_decrypted = f"{TEST_DIR}/ecc-decrypted.txt"
        self._private_file = os.path.join(CONFIG_DIR, "ecc-private.txt")
        self._public_file = os.path.join(CONFIG_DIR, "ecc-public.txt")
        self._config_file = os.path.join(CONFIG_DIR, "ecc-config.txt")
        self._test_input = os.path.join(TEST_DIR, "msg.txt")
        self._test_encrypted = os.path.join(TEST_DIR, "ecc-encrypted.txt")
        self._test_decrypted = os.path.join(TEST_DIR, "ecc-decrypted.txt")
        self.prime_bit = ECC_PRIME_BIT        # berapa bit prime p yang di-generate
        self.coef_bit = ECC_COEF_BIT          # berapa bit koefisien elliptic curve yang di-generate
        if self.debug:
            level = logging.INFO
            fmt = '[%(levelname)s] - %(message)s'
            # fmt = '[%(levelname)s] %(asctime)s - %(message)s'
            logging.basicConfig(level=level, format=fmt)
        pass
    
    def update_config(self):
        self.generate_config(prime_bit=self.prime_bit, coef_bit=self.coef_bit)
        self.store_config()

    def initiate(self, generate_new_config: bool, generate_new_keys: bool):
        if generate_new_config:
            self.update_config()
        self.read_config()

        if generate_new_keys:
            self.update_keys()
        self.read_keys()

    def generate_config(self, prime_bit:int=None, coef_bit:int=None):
        if prime_bit is None:
            prime_bit = self.prime_bit
        if coef_bit is None:
            coef_bit = self.coef_bit
        self._a = randrange(-1 * (1<<coef_bit), 1<<coef_bit)
        self._b = randrange(-1 * (1<<coef_bit), 1<<coef_bit)
        generator = util.PrimeGenerator(prime_bit)
        self._p = generator.generate_prime()

        if self.debug:
            logging.debug(f"Generate elliptic curve:")
            logging.debug(f"y^2 = x^4 + {self._a}x + {self._b}")
            logging.debug(f"p:{self._p}")
            # print(f"y^2 = x^4 + {self._a}x + {self._b}\np:{self._p}")
    
    def store_config(self):
        configuration = f"{self._a} {self._b} {self._p}".encode("utf-8")
        util.writefile(self._config_file, configuration)

    def read_config(self):
        self._a, self._b, self._p = [int(i) for i in util.readfile(self._config_file).decode("utf-8").split(' ')]

        if self.debug:
            logging.debug(f"Read elliptic curve:")
            logging.debug(f"y^2 = x^3 + {self._a}x + {self._b}")
            logging.debug(f"p = {self._p}")
            # print(f"y^2 = x^3 + {self._a}x + {self._b}\np = {self._p}")
    
    def get_config(self):
        return self._a, self._b, self._p, self.point
    
    def get_config_a(self):
        return self._a
    def get_config_b(self):
        return self._b
    def get_config_p(self):
        return self._p
    def set_config_a(self, a):
        self._a = a
    def set_config_b(self, b):
        self._b = b
    def set_config_p(self, p):
        self._p = p

    def update_keys(self):
        self.generate_keys()
        self.store_keys()

    def generate_keys(self):
        n_bits = self.prime_bit
        # Private keys
        self.pri_a = randrange(1 << (n_bits - 1), 1 << n_bits)
        self.pri_b = randrange(1 << (n_bits - 1), 1 << n_bits)
        # self.k = randrange(self._p)
        self.k = self._generate_k()
        self.point = self.determine_start_point()

        # Public keys
        self.pub_a = self.multiply_point(self.point, self.pri_a)
        self.pub_b = self.multiply_point(self.point, self.pri_b)
    
    def store_keys(self):
        private = f"{self.pri_a} {self.pri_b} {self.k}\n"
        private += f"{self.point[0]} {self.point[1]}"
        util.writetxt(self._private_file, private)

        public = f"{self.pub_a[0]} {self.pub_a[1]}\n"
        public += f"{self.pub_b[0]} {self.pub_b[1]}"
        util.writetxt(self._public_file, public)
    
    def read_keys(self):
        private = util.readtxt(self._private_file)
        self.pri_a, self.pri_b, self.k = [int(i) for i in private[0].split(' ')]
        x, y = private[1].split(' ')
        self.point = (int(x), int(y))

        public = util.readtxt(self._public_file)
        xa, ya = public[0].split(' ')
        self.pub_a = (int(xa), int(ya))
        xb, yb = public[1].split(' ')
        self.pub_b = (int(xb), int(yb))

    def set_pub_key(self, pub):
        self._public_file = pub
        self.read_keys()

    def set_pri_key(self, pri):
        self._private_file = pri
        self.read_keys()

    # Private keys
    def get_key_pri_a(self):
        return self.pri_a
    def get_key_pri_b(self):
        return self.pri_b
    def get_key_starting_point(self):
        return self.point
    def set_key_pri_a(self, a):
        self.pri_a = a
    def set_key_pri_b(self, b):
        self.pri_b = b
    def set_key_starting_point(self, point):
        self.point = point
    def _generate_k(self):
        return randrange(self._p//2, self._p)
    
    def get_key_point_a(self):
        return self.pub_a
    def get_key_point_b(self):
        return self.pub_b
    def set_key_point_a(self, pointa):
        self.pub_a = pointa
    def set_key_point_b(self, pointb):
        self.pub_b = pointb

    def show_info(self):
        logging.info(f"ECC equation: y^2 = x^3 + {self._a}x + {self._b}")
        logging.info(f"p = {self._p}")
        logging.info("===== PRIVATE KEYS =====")
        logging.info(f"Starting point (PB): {self.point}")
        logging.info(f"pri_a = {self.pri_a}")
        logging.info(f"pri_b = {self.pri_b}")
        logging.info(f"k = {self.k}")
        logging.info("===== PUBLIC KEYS =====")
        logging.info(f"pub_a = {self.pub_a}")
        logging.info(f"pub_b = {self.pub_b}")
    
    def private_key_info(self):
        result = ""
        txt_a = f"+ {self._a}" if self._a > 0 else f"- {abs(self._a)}"
        txt_b = f"+ {self._b}" if self._b > 0 else f"- {abs(self._b)}"
        result += f"ECC equation: y^2 = x^3 {txt_a}x {txt_b}\n"
        result += f"p = {self._p}\n"
        result += "===== PRIVATE KEYS =====\n"
        result += f"Starting point (PB): {self.point}\n"
        result += f"Private key Alice = {self.pri_a}\n"
        result += f"Private key Bob = {self.pri_b}\n"
        return result
    
    def public_key_info(self):
        result = ""
        result += "===== PUBLIC KEYS =====\n"
        result += f"Public key Alice = ({self.pub_a[0]}, {self.pub_a[1]})\n"
        result += f"Public key Bob = ({self.pub_b[0]}, {self.pub_b[1]})\n"
        return result

    
    def _y_square(self, x: int):
        return x**3 + self._a * x + self._b

    def _generate_square_map(self):
        # Set up map
        # <key, value> where key and value in {0, 1, ..., p-1} and key is i^2 mod p for every p in [0, p)
        self._map = defaultdict(list)
        i = 0
        for n in range(self._p):
            if i % (1<<32) == 0: print(i, end=' ')
            n_squared = pow(n, 2, self._p)
            self._map[n_squared].append(n)
            i += 1
        print(self._map)
    
    def generate_points(self):
        self._generate_square_map()

        self._points = []
        for x in range(self._p):
            rhs = self._y_square(x)
            # print(x, rhs, rhs%self._p)
            # if rhs >= 0:
            # print(rhs, end='#')
            # y = math.isqrt(rhs)
            y_squared = rhs % self._p
            for y_valid in self._map[y_squared]:
                # print(y, end='#')
                self._points.append((x, y_valid))
                # self._points.append((x, y%self._p))
        
        if self.debug:
            print(self._points)
    
    def determine_start_point(self):
        while True:
            x = randrange(self._p)
            # print("failed?", x)
            y_squared = self._y_square(x) % self._p
            result = util.modular_sqrt(y_squared, self._p)
            if result != 0:
                return (x, result)

    def add_points(self, P, Q):
        if P == INFPOINT: return Q
        if Q == INFPOINT: return P

        if P[0] == Q[0]:
            if P[1] == Q[1]: return self.double_point(P)
            if P[1] != Q[1]: return INFPOINT

        # m = ((P[1] - Q[1]) / (P[0] - Q[0])) % self._p
        m = (P[1]-Q[1]) * pow(P[0]-Q[0], -1, self._p) % self._p
        x = (m*m - P[0] - Q[0]) % self._p
        y = (m*(P[0] - x) - P[1]) % self._p

        return (x, y)
    
    def sub_points(self, P, Q):
        Qa = (Q[0], (-Q[1]) % self._p)
        return self.add_points(P, Qa)
    
    def double_point(self, P):
        assert(P != INFPOINT)

        # m = ((3 * P[0]**2 + self._a) / (2*P[1])) % self._p
        m = (3*P[0]*P[0] + self._a) * pow(2*P[1], -1, self._p) % self._p
        x = (m*m - 2*P[0]) % self._p
        y = (m * (P[0] - x) - P[1]) % self._p

        return (x, y)
    
    def multiply_point(self, P, k:int):
        if k == 1:
            # Basis
            return P
        
        if k%2 == 1:
            # if k is odd
            # return 2 (k-1)P + P
            half_P = self.multiply_point(P, k//2)
            return self.add_points(self.double_point(half_P), P)
        else:
            # if k is even
            # return 2 (k-1)P
            half_P = self.multiply_point(P, k//2)
            return self.double_point(half_P)
    
    def encrypt(self, points):
        # PC = [ (kB), (PM + kPB) ]
        # PB = pub_b = b.B
        result = []
        k = self.k
        pb = self.pub_b
        start_point = self.point
        for pm in points:
            kb = self.multiply_point(start_point, k)
            pmkpb = self.add_points(pm, self.multiply_point(pb, k))
            result.append([kb, pmkpb])
            k = self._generate_k()
        
        return result
    
    def decrypt(self, encrypted):
        # PC = [ (kB), (PM + kPB) ] = [ (kB), (PM + kbB) ]
        # PB = bB
        result = []
        b = self.pri_b
        for pair in encrypted:
            point0 = pair[0]    # kB
            point1 = pair[1]    # PM + kPB
            bkb = self.multiply_point(point0, b)    # bkB
            pm = self.sub_points(point1, bkb)       # PM + kPB - bkB
            # assert(self.add_points(pm, point0) == point1)
            # assert(self.multiply_point(point0, b) == self.multiply_point(self.pub_b, self.k))
            result.append(pm)
        return result

class ECCEncoder():
    # Read per char, only accepts ASCII characters
    def __init__(self):
        self.debug = False
        self._config_file = f"{CONFIG_DIR}/ecc-config.txt"
        self._test_input = f"{TEST_DIR}/ecc-input.txt"
        self._test_encrypted = f"{TEST_DIR}/ecc-encrypted.txt"
        self._test_decrypted = f"{TEST_DIR}/ecc-decrypted.txt"
        # self._test_input = f"{TEST_DIR}/ecc-input.txt"
        # self._test_encrypted = f"{TEST_DIR}/ecc-encrypted.txt"
        # self._test_decrypted = f"{TEST_DIR}/ecc-decrypted.txt"
        self.k = 10
        self.p = int(util.readfile(self._config_file).decode("utf-8").split(' ')[2])
        self.encoding_byte_size = ECC_PRIME_BIT // 8

        if self.debug:
            level = logging.INFO
            fmt = '[%(levelname)s] %(asctime)s - %(message)s'
            logging.basicConfig(level=level, format=fmt)

    def encode(self, dirname=None):
        if dirname == None:
            dirname = self._test_input
        message = util.readtxt(dirname)
        message = ''.join(message)

        result = []
        k = self.k
        for c in message:
            i = 1
            m = ord(c)
            x = m*k + i
            x_decoded = util.modular_sqrt(x, self.p)
            while x_decoded in [-1, 0]:
                i += 1
                x = m*k + i
                x_decoded = util.modular_sqrt(x, self.p)
            
            result.append((x, x_decoded))
        
        if self.debug:
            logging.info("ecc.encode:")
            logging.info(result)
        return result
    
    def decode(self, points):
        result = ""
        k = self.k
        for point in points:
            x = int(point[0])
            m = (x-1) // k
            result += chr(m)
        return result
    
    def point2byte(self, point):
        '''
            [DESC]
                Convert <point> (a list containing x and y value) into bytes
                The x and y values are in the Gallois Field p,
                where p is a prime number of size ECC_PRIME_BIT bits or ECC_PRIME_BIT//8 bytes
                Each of these x and y values are then converted into a
                bytes type of size ECC_PRIME_BIT//8 bytes
                Add necessary b'\x00' bytes as padding in front of the converted values
            [PARAMS]
                point: list[int, int]   { a point from the ECC ecnryption result }
            [RETURN]
                a bytes value from the point conversion
        '''
        x_val = point[0]
        y_val = point[1]
        x_byte = util.hex2byte(hex(x_val)[2:])
        y_byte = util.hex2byte(hex(y_val)[2:])
        # try:
        #     x_byte = util.hex2byte(hex(x_val)[2:])
        #     y_byte = util.hex2byte(hex(y_val)[2:])
        # except:
        #     logging.warning("x_val: " + x_val)
        #     logging.warning("y_val: " + y_val)
        #     exit(1)

        # Add padding
        x_req_padding_bytes = self.encoding_byte_size - len(x_byte)
        x_byte = b'\x00' * x_req_padding_bytes + x_byte
        y_req_padding_bytes = self.encoding_byte_size - len(y_byte)
        y_byte = b'\x00' * y_req_padding_bytes + y_byte

        return x_byte + y_byte
    
    def byte2point(self, byte: bytes):
        '''
            [DESC]
                Convert <byte> back into a point of x and y value
                <byte>'s size is 2 * (ECC_PRIME_BIT // 8) bytes
                These x and y values is then used for ECC decryption
            [PARAMS]
                byte: bytes     { containing the x and y values in bytes type }
            [RETURN]
                a point (list of x and y value)
        '''
        x_byte = byte[:self.encoding_byte_size]
        y_byte = byte[self.encoding_byte_size:]
        x_int = int.from_bytes(x_byte, 'big')
        y_int = int.from_bytes(y_byte, 'big')
        point = [x_int, y_int]
        return point
    
    def write_encrpyted(self, encrypted):
        '''"""
            [DESC]
                Parse encrypted into bytes to be written into a file
                encrypted is the ecc result in the form of list of pairs of 2 Point
                    Each point has (x, y) value which is in the Gallois Field p
                    So, 1 <= x, y <= p-1
                Since we know that p is a ECC_PRIME_BIT bit prime number, we can
                encode each of these x and y values into ECC_PRIME_BIT bytes
            [PARAMS]
                encrypted: list[Point, Point]   { the result of ECC cipher process }
        '''
        result = b""
        for pair in encrypted:
            point0 = pair[0]
            point1 = pair[1]
            point0_byte = self.point2byte(point0)
            point1_byte = self.point2byte(point1)
            result += point0_byte + point1_byte
            # result += f"{point0[0]} {point0[1]} {point1[0]} {point1[1]}"
            # result += "\n"
        # result = result.encode()
        result = util.byte2hex(result)
        # util.writefile(self._test_encrypted, result)
        util.writetxt(self._test_encrypted, result)
    
    def read_encrypted(self):
        '''
            [DESC]
                Reads from ecc-encrypted.txt to be decoded into
                list of pairs of 2 points
                Parse each item in the file by ECC_PRIME_BIT bytes
                For each 4 items, they will be decoded into
                the (x, y) values for the pair of 2 points
        '''
        # b = util.readfile(self._test_encrypted)
        b = util.readtxt(self._test_encrypted)
        b = ''.join([e for e in b])
        b = util.hex2byte(b)
        # lines = b.decode().split('\n')[:-1]
        # lines = util.readtxt(self._test_encrypted)
        result = []
        point_size = 2 * self.encoding_byte_size    # in bytes
        pair_size = 2 * point_size                 # in bytes
        n_pair = len(b) // pair_size

        for i in range(n_pair):
            # Read a pair of points
            offset = i * pair_size
            # Read point 0
            point0_byte = b[offset : offset + point_size]
            point0 = self.byte2point(point0_byte)
            # Read point 1
            point1_byte = b[offset + point_size : offset + 2 * point_size]
            point1 = self.byte2point(point1_byte)

            result.append([point0, point1])
        # for line in lines:
        #     point00, point01, point10, point11 = [int(i) for i in line.split(' ')]

        #     result.append([(point00, point01), (point10, point11)])
        return result


def ecc_demo():
    start = time.perf_counter()
    ecc = ECC()
    # ecc.udpate_config()
    ecc.initiate()
    ecc.show_info()
    starting_point = ecc.point
    k = 1 << 128
    result = ecc.multiply_point(starting_point, k)
    
    logging.info(result)
    logging.info("Compute time:", time.perf_counter()-start)

def encode_demo():
    e = ECCEncoder()
    result = e.encode()
    print(result)
    # result is plain
    
    e.write_to_txt(result)
    
    
    result = e.decode()
    print(result)

def simulate_ecc():
    # Initiate ECC
    ecc = ECC()

    ecc.initiate(generate_new_config=True, generate_new_keys=True)
    # ecc.show_info()
    print(ecc.private_key_info())
    print(ecc.public_key_info())

    ecc_encoder = ECCEncoder()
    
    encoded_message = ecc_encoder.encode()
    logging.info(f"Encoded message -> points ({len(encoded_message)}):")
    for i, item in enumerate(encoded_message[:10]):
        print(f"{i})       {item}")

    encrypted = ecc.encrypt(encoded_message)
    logging.info(f"Encrypted ({len(encrypted)}):")
    for i, item in enumerate(encrypted[:10]):
        print(f"{i})       {item}")
    ecc_encoder.write_encrpyted(encrypted)

    logging.info("##### ENCRYPTION END #####")
    # = = = = = =
    logging.info("##### DECRYPTION START #####")
    decoded_ciphertext = ecc_encoder.read_encrypted()
    logging.info(f"Retrieved encrypted bin -> list ({len(decoded_ciphertext)}):")
    for i, item in enumerate(decoded_ciphertext[:10]):
        print(f"{i})       {item}")
    
    decrypted_ciphertext = ecc.decrypt(decoded_ciphertext)
    logging.info(f"ECC decrypted ciphertext points -> points of encoded message ({len(decrypted_ciphertext)}):")
    for i, item in enumerate(decrypted_ciphertext[:10]):
        print(f"{i})       {item}")
    
    plaintext = ecc_encoder.decode(decrypted_ciphertext)

    logging.info("Plaintext: " + plaintext)
    util.writetxt("test/ecc-decrypted.txt", plaintext)

    # PC = [ (kB), (PM + kPB) ] = [ (kB), (PM + kbB) ]
    # PB = bB

def point_byte_test():
    eccc = ECCEncoder()
    point = (5105610199983925356685096756448124416198892764601618299306045273471290546495, 38477108760889943752512839604849054809420737740480385215215238249923595437515)
    print(point)
    res = eccc.point2byte(point)
    print(res)
    res2 = eccc.byte2point(res)
    print(res2)

    pass

if __name__ == "__main__":
    # ecc_demo()
    # setup_logger()
    simulate_ecc()
    # point_byte_test()
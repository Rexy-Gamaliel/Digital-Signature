import utility as util
from constant import TEST_DIR


class SHA():
    '''
        [DESC]
            SHA 256 hash algorithm, according to Wikipedia
            https://en.wikipedia.org/wiki/SHA-2#Pseudocode
    '''
    def __init__(self):
        self.debug = False
        self.nice = True    # Don't change to False yet as it is currently not implemented
        self._hash_values = self.__init_hash_values()
        self._table = self.__init_table()

        pass

    def __init_hash_values(self):
        """
            Initialize the first eight 32-bit hash values
            (first 32 bits of the fractional parts of
            the square roots of the first 8 primes (2 to 19))
        """
        first_8_primes_sqrt_frac = [
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19,
        ]
        hash_values = [int.to_bytes(i, 32//8, 'big') for i in first_8_primes_sqrt_frac]
        if self.nice:
            hash_values = [NiceBytes(b) for b in hash_values]
        return hash_values
    
    def __init_table(self):
        """
            Initialize the 64 32bit-constants for table T
            (first 32 bits of the fractional parts of
            the cube roots of the first 64 primes (2 to 311))
        """
        first_64_primes_cbrt_frac = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ]
        table = [int.to_bytes(i, 32//8, 'big') for i in first_64_primes_cbrt_frac]
        if self.nice:
            table = [NiceBytes(b) for b in table]
        return table

    def __padding(self, message: bytes):
        """
            [DESC]
                First and second step of hashing: add padding to message
                Done by appending \x80 byte, followed by additional
                \x00 bytes such that the appended message's length in bits
                is equivalent to 448 (mod 512).
                Then add the original message length (in 64-bits big endian)
                to the end of the message
            [PARAMS]
            message: bytes  { message to be processed }
                              len(message) in bits % 8 == 0
            [RETURN]
                message + padding
        """
        message_size_bit = len(message) * 8
        
        # Add \x80 byte
        message += b'\x80'
        
        # Add \x00 bytes
        n_zeros = ((448 - (message_size_bit + 8)) % 512) // 8
        message += b'\x00' * n_zeros
        
        # Add original message length
        message_size_padding = int.to_bytes(message_size_bit, 64//8, 'big')
        message += message_size_padding
        return message
    
    def __break_into_chunks(self, message: bytes):
        """
            [DESC]
                Break the (k*512) bits long message after padding
                into k 512-bits chunks
            [PARAMS]
                message: bytes  { message after padding }
                                { len(message) in bits is of k*512 }
            [RETURN]
                list of 512-bits of chunks
        """
        chunk_size = 512//8     # in byte
        message_size = len(message)
        k = message_size // chunk_size
        return [message[i*chunk_size: (i+1)*chunk_size] for i in range(k)]

    def __init_message_schedule(self, chunk: bytes):
        """
            [DESC]
                Return a 64-entry message schedule array w[0..63]
                Each entry is a 32-bit (4-byte) word, initialized with all zeros
                Then, set the first 16 word entries to chunk
            [PARAMS]
                chunk: bytes    { a 512-bit chunk from message }
            [RETURN]
                An array of bytes
        """
        word_size = 4   # in bytes
        msg_schedule = [b'\x00' * word_size] * 64

        # break chunks into 16 32-bit or 4-byte words
        chunk_words = [chunk[i*word_size:(i+1)*word_size] for i in range(16)]
        for i, word in enumerate(chunk_words):
            msg_schedule[i] = word
        
        if self.nice:
            for i, word in enumerate(msg_schedule):
                msg_schedule[i] = NiceBytes(msg_schedule[i])
        return msg_schedule

    def __extend_message_schedule(self, msc):
        """
            [DESC]
                'Extend' the first 16 words in message schedule into the 48 words
            [PARAMS]
                msc: list[bytes]    { the message schedule }
                                    { consists of 64 elements, each is a 4-byte word }
            [RETURN]
                processed (extended) message schedule
        """
        for i in range(16, 64):
            if self.nice:
                w1 = msc[i-15]
                w11 = w1.right_rotate(7)
                w12 = w1.right_rotate(18)
                w13 = w1 >> 3
                s0 = w11 ^ w12 ^ w13
                
                w2 = msc[i-2]
                w21 = w2.right_rotate(17)
                w22 = w2.right_rotate(19)
                w23 = w2 >> 10
                s1 = w21 ^ w22 ^ w23

                msc[i] = msc[i-16] + s0 + msc[i-7] + s1
        
            else:
                w1 = msc[i-15]
                w11 = self.right_rotate(w1, 7)
                w12 = self.right_rotate(w1, 18)
                w13 = self.right_rotate(w1, 3)
                s0 = self.xor_bytes(w11, w12, w13)
                
                w2 = msc[i-2]
                w21 = self.right_rotate(w2, 17)
                w22 = self.right_rotate(w2, 19)
                w23 = self.right_rotate(w2, 10)
                s1 = self.xor_bytes(w21, w22, w23)

                msc[i] = self.add_bytes(msc[i-16], s0, msc[i-7], s1)

        return msc

    @staticmethod
    def right_rotate(chunk: bytes, n: int) -> bytes:
        """
            [DESC]
                Perform right right_rotate on chunk by n bits
                Example:
                (here chunk is presented in binary, not bytes)
                # b'\x4e' → b'\x27'
                right_rotate('01001110', 1) → '00100111'
                # b'\x4e' → b'\xc9'
                right_rotate('01001110', 3) → '11001001'
            [PARAMS]
                chunk: bytes    { bytes to be rotated }
            [RETURN]
                rotated chunk
        """
        # Convert chunk to binary representation
        chunk_size = len(chunk) * 8     # in bits
        fmt = "{0:0" + str(chunk_size) +  "b}"
        chunk_bits = "{}".format(fmt).format(int.from_bytes(chunk, 'big'))
        # Rotate
        n_rotation = n % chunk_size
        rotated_bits = chunk_bits[chunk_size-n_rotation:] + chunk_bits[:chunk_size-n_rotation]
        # Convert back to byte
        rotated_chunk = int.to_bytes(int(rotated_bits, 2), len(chunk), 'big')
        return rotated_chunk
    
    @staticmethod
    def right_shift(chunk: bytes, n: int) -> bytes:
        """
            [DESC]
                Perform right shift on chunk by n bits
                Example:
                (here chunk is presented in binary, not bytes)
                # b'\x4e' → b'\x27'
                right_shift('01001110', 1) → '00100111'
                # b'\x4e' → b'\x09'
                right_shift('01001110', 3) → '00001001'
                # b'\x4e' → b'\x00'
                right_shift('01001110', 0) → '00000000'
            [PARAMS]
                chunk: bytes    { bytes to be shifted }
            [RETURN]
                shifted chunk
        """
        chunk_size = len(chunk)
        chunk_int = int.from_bytes(chunk, 'big')
        chunk_int >>= n
        shifted_chunk = int.to_bytes(chunk_int, chunk_size, 'big')
        return shifted_chunk

    @staticmethod
    def add_bytes(*args: bytes) -> bytes:
        """
            [DESC]
                Perform binary addition for each bytes
                Bytes are assumed to be of same size
                Addition is done in modulo 2**(size of bytes in bits)
            [PARAMS]
                any number of bytes of same size
            [RETURN]
                binary addition of all bytes in argument
        """
        if len(args) != 0:
            byte_size = len(args[0]) * 8    # in bits
            mod_base = 2 ** byte_size
            result_int = 0
            for arg in args:
                bytes_int = int.from_bytes(arg, 'big')
                result_int = (result_int + bytes_int) % mod_base
            result_bytes = int.to_bytes(result_int, len(args[0]), 'big')
            return result_bytes
        raise Exception("Empty argument")
    
    @staticmethod
    def xor_bytes(*args: bytes) -> bytes:
        """
            [DESC]
                Perform binary XOR for each bytes
                Bytes are assumed to be of same size
            [PARAMS]
                any number of bytes of same size
            [RETURN]
                binary XOR of all bytes in argument
        """
        if len(args) != 0:
            result_int = 0
            for arg in args:
                bytes_int = int.from_bytes(arg, 'big')
                result_int = result_int ^ bytes_int
            result_bytes = int.to_bytes(result_int, len(args[0]), 'big')
            return result_bytes
        raise Exception("Empty argument")
    
    @staticmethod
    def and_bytes(*args: bytes) -> bytes:
        """
            [DESC]
                Perform binary AND for each bytes
                Bytes are assumed to be of same size
            [PARAMS]
                any number of bytes of same size
            [RETURN]
                binary AND of all bytes in argument
        """
        if len(args) != 0:
            result_int = int.from_bytes(b'\xff'*len(args[0]), 'big')
            for arg in args:
                bytes_int = int.from_bytes(arg, 'big')
                result_int = result_int & bytes_int
            result_bytes = int.to_bytes(result_int, len(args[0]), 'big')
            return result_bytes
        raise Exception("Empty argument")
    
    @staticmethod
    def or_bytes(*args: bytes) -> bytes:
        """
            [DESC]
                Perform binary OR for each bytes
                Bytes are assumed to be of same size
            [PARAMS]
                any number of bytes of same size
            [RETURN]
                binary OR of all bytes in argument
        """
        if len(args) != 0:
            result_int = 0
            for arg in args:
                bytes_int = int.from_bytes(arg, 'big')
                result_int = result_int | bytes_int
            result_bytes = int.to_bytes(result_int, len(args[0]), 'big')
            return result_bytes
        raise Exception("Empty argument")
    
    @staticmethod
    def not_bytes(arg: bytes) -> bytes:
        """
            [DESC]
                Perform binary NOT for a bytes
            [PARAMS]
                any number of bytes of same size
            [RETURN]
                binary NOT of the bytes in argument
        """
        bytes_int = int.from_bytes(arg, 'big')
        max_int = 2 ** (len(arg) * 8) - 1
        result_int = max_int - bytes_int
        result_bytes = int.to_bytes(result_int, len(arg), 'big')
        return result_bytes

    def hash(self, message: bytes):
        """
        
        """
        message = self.__padding(message)
        chunks = self.__break_into_chunks(message)
        
        hash_values = self._hash_values
        first = True
        for chunk in chunks:
            message_schedule = self.__init_message_schedule(chunk)
            message_schedule = self.__extend_message_schedule(message_schedule)
            if first:
                print(message_schedule[16])
            
            # print("Message Schedule from chunk:", chunk)
            # print(message_schedule)
            # break

            a = hash_values[0]
            b = hash_values[1]
            c = hash_values[2]
            d = hash_values[3]
            e = hash_values[4]
            f = hash_values[5]
            g = hash_values[6]
            h = hash_values[7]

            # Compression Function main loop
            if self.nice:
                for i in range(64):
                    # compute s1
                    s1 = e.right_rotate(6) ^ e.right_rotate(11) ^ e.right_rotate(25)

                    # compute s0
                    ch = (e & f) ^ ((~e) & g)
                    temp1 = h + s1 + ch + self._table[i] + message_schedule[i]
                    s0 = a.right_rotate(2) ^ a.right_rotate(13) ^ a.right_rotate(22)
                    maj = (a & b) ^ (a & c) ^ (b & c)
                    temp2 = s0 + maj
                    
                    # scramble
                    h = g
                    g = f
                    f = e
                    e = d + temp1
                    d = c
                    c = b
                    b = a
                    a = temp1 + temp2
                
                # assign new hash values
                hash_values[0] += a
                hash_values[1] += b
                hash_values[2] += c
                hash_values[3] += d
                hash_values[4] += e
                hash_values[5] += f
                hash_values[6] += g
                hash_values[7] += h
            
            else:
                pass
            first = False
        
        digest = b''.join(hash_values)
        return digest

class SHAEncoder():
    """
        Tidak terlalu guna but okay
    """
    def __init__(self, inputpath=None, outputpath=None):
        if inputpath is None:
            inputpath = f"{TEST_DIR}/sha-input.txt"
        self.inputpath = inputpath

        if outputpath is None:
            outputpath = f"{TEST_DIR}/sha-output.txt"
        self.outputpath = outputpath
        pass
    
    def read_file(self):
        message = util.readfile(self.inputpath)
        return message
    
    def write_file(self, content: bytes):
        # util.writefile(self.outputpath, content)
        util.writetxt(self.outputpath, content)

class NiceBytes(bytes):
    """
        Add useful operators to built-in bytes data type
        so the equation looks nicer :)
        From
            SHA.add_bytes(bytes1, bytes2, ...)
        to
            bytes1 + bytes2 + ...
        etc.
    """
    def __new__(cls, val:bytes=None):
        return super().__new__(cls, val)
    def __init__(self, val:bytes=None):
        self = val
    def __add__(self, other):
        return NiceBytes(SHA.add_bytes(self, other))
    def __xor__(self, other):
        return NiceBytes(SHA.xor_bytes(self, other))
    def __and__(self, other):
        return NiceBytes(SHA.and_bytes(self, other))
    def __or__(self, other):
        return NiceBytes(SHA.or_bytes(self, other))
    def __invert__(self):
        return NiceBytes(SHA.not_bytes(self))
    def __rshift__(self, n: int):
        return NiceBytes(SHA.right_shift(self, n))
    def right_rotate(self, n: int):
        return NiceBytes(SHA.right_rotate(self, n))


def test():    
    b1 = NiceBytes(b'\x4e')
    print(f"{b1 = } = 01001110")
    b2 = NiceBytes(b'\x9e')
    print(f"{b2 = } = 10011110")
    print(f"{b1 + b2 = } = 11101100?")
    print(f"{b1 ^ b2 = } = 11010000?")
    print(f"{b1 & b2 = } = 00001110?")
    print(f"{b1 | b2 = } = 11011110?")
    print(f"{~b1 = } = 10110001?")
    print(f"{b1.right_rotate(1) = }")
    print(f"{b1 >> 3 = }")

    # sha = SHA()
    # sha.hash(b"Hello\World!")
    pass

def simulate_sha256():
    sha = SHA()
    sha_encoder = SHAEncoder()
    message = sha_encoder.read_file()

    hash_result = sha.hash(message)

    # hash_result = byte2hex(hash_result)       # Uncomment to see hex representation
    sha_encoder.write_file(hash_result)

if __name__ == "__main__":
    # test()
    simulate_sha256()
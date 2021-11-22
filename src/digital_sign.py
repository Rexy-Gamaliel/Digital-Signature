import os
from sha import SHA, SHAEncoder
from ecc import ECC, ECCEncoder
import utility as util
from constant import TEST_DIR, CONFIG_DIR, BEGIN_SIGN, END_SIGN
from constant import ECC_ENCRYPTION_OUTPUT_FILE, ECC_DECRYPTION_OUTPUT_FILE, ECC_TEST_INPUT_FILE
from constant import ECC_CONFIG_FILE, ECC_PRIVATE_KEY_FILE, ECC_PUBLIC_KEY_FILE

ecc = ECC()
ecc_encoder = ECCEncoder()
MSG_FILE = os.path.join(TEST_DIR, "msg.txt")
SIGNED_FILE = os.path.join(TEST_DIR, "msg-signed.txt")
SIGN_FILE = os.path.join(TEST_DIR, "sign")
PUB_FILE = os.path.join(CONFIG_DIR, ECC_PUBLIC_KEY_FILE)
PRI_FILE = os.path.join(CONFIG_DIR, ECC_PRIVATE_KEY_FILE)
ecc.initiate(generate_new_config=False, generate_new_keys=False)

def sign_txt(filename = MSG_FILE, target = SIGNED_FILE, private_key = PRI_FILE):
    sha = SHA()
    sha_encoder = SHAEncoder()
    ecc.set_pri_key(private_key)

    text = util.readtxt(filename)
    text = ''.join(text)
    bytes_text = text.encode('utf-8')

    ''' HASH MSG '''
    text_hash = util.byte2hex(sha.hash(bytes_text))

    util.writetxt(f"{TEST_DIR}/{ECC_TEST_INPUT_FILE}", text_hash)

    ''' ENCRYPT HASH MESSAGE '''
    # ecc.show_info()
    encode_hash = ecc_encoder.encode()
    encrypted_hash = ecc.encrypt(encode_hash)
    ecc_encoder.write_encrpyted(encrypted_hash)

    ''' MAKE SIGNATURE FILE '''
    text = util.readtxt(filename)
    signature = util.readtxt(f"{TEST_DIR}/ecc-encrypted")

    ''' SAVE SIGNATURE FILE '''
    util.writetxt("test/sign", ''.join(signature))

    ''' SAVE SIGNED FILE '''
    text.append(BEGIN_SIGN + "\n")
    for x in signature:
        text.append(x)
    text.append(END_SIGN)

    util.writetxt(target,''.join(text))

def verify_sign(filename = SIGNED_FILE, public_key = PUB_FILE):
    sha = SHA()
    sha_encoder = SHAEncoder()
    ecc.set_pub_key(public_key)

    ''' READ TEXT FILE '''
    text = util.readtxt(filename)
    str_text = ''.join(text)

    ''' SPLIT MESSAGE AND SIGNATURE '''
    split = str_text.split(BEGIN_SIGN + "\n")
    msg = split[0]
    signature = split[1].split(END_SIGN)[0]

    ''' GET HASH MESSAGE '''
    bytes_msg = msg.encode('utf-8')
    hash_msg = util.byte2hex(sha.hash(bytes_msg))

    ''' GET DECRYPTED SIGNATURE '''
    util.writetxt(f"{TEST_DIR}/ecc-encrypted", signature)
    ret = ecc_encoder.read_encrypted()
    points = ecc.decrypt(ret)
    decrypted_sign = ecc_encoder.decode(points)

    if hash_msg == decrypted_sign:
        return True
    else:
        return False

def verify_sign_with_file(filename = MSG_FILE, sign = SIGN_FILE, public_key = PUB_FILE):
    sha = SHA()
    sha_encoder = SHAEncoder()
    ecc.set_pub_key(public_key)

    ''' READ TEXT FILE '''
    text = util.readtxt(filename)
    msg = ''.join(text)

    ''' GET HASH MESSAGE '''
    bytes_msg = msg.encode('utf-8')
    hash_msg = util.byte2hex(sha.hash(bytes_msg))

    ''' GET SIGN FILE '''
    signature = util.readtxt(sign)
    
    ''' GET DECRYPTED SIGNATURE '''
    util.writetxt(f"{TEST_DIR}/ecc-encrypted", ''.join(signature))
    ret = ecc_encoder.read_encrypted()
    points = ecc.decrypt(ret)
    decrypted_sign = ecc_encoder.decode(points)

    if hash_msg == decrypted_sign:
        return True
    else:
        return False

def simulate_sign():
    sign_txt()
    result = verify_sign()
    result2 = verify_sign_with_file()
    print("Verifying result : " + str(result))
    print("Verifying result with sign file: " + str(result2))


if __name__ == "__main__":
    simulate_sign()

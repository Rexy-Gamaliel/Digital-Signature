import os
from sha import SHA, SHAEncoder
from ecc import ECC, ECCEncoder
import utility as util
from constant import TEST_DIR, CONFIG_DIR, DEMO_DIR, BEGIN_SIGN, END_SIGN
from constant import ECC_ENCRYPTION_OUTPUT_FILE, ECC_DECRYPTION_OUTPUT_FILE, ECC_TEST_INPUT_FILE
from constant import ECC_CONFIG_FILE, ECC_PRIVATE_KEY_FILE, ECC_PUBLIC_KEY_FILE
from constant import SIGNED_MESSAGE_FILE, SIGNATURE_FILE

ecc = ECC()
ecc_encoder = ECCEncoder()
MSG_FILE = os.path.join(TEST_DIR, "msg.txt")
SIGNED_FILE = os.path.join(TEST_DIR, SIGNED_MESSAGE_FILE)
SIGN_FILE = os.path.join(TEST_DIR, SIGNATURE_FILE)
PUB_FILE = os.path.join(CONFIG_DIR, ECC_PUBLIC_KEY_FILE)
PRI_FILE = os.path.join(CONFIG_DIR, ECC_PRIVATE_KEY_FILE)
ECC_INPUT = os.path.join(TEST_DIR, "ecc-input.txt")
ECC_RESULT = os.path.join(TEST_DIR, ECC_ENCRYPTION_OUTPUT_FILE)

ecc.initiate(generate_new_config=False, generate_new_keys=False)

def sign_txt(filename=MSG_FILE, target=SIGNED_FILE, private_key=PRI_FILE, pisah:bool=False):
    # if pisah: target adalah file signature di-output
    # else: target adalah file message+signature di-output
    sha = SHA()
    sha_encoder = SHAEncoder()
    ecc.set_pri_key(private_key)

    text = util.readtxt(filename)
    text = ''.join(text)
    bytes_text = text.encode('utf-8')

    ''' HASH MSG '''
    text_hash = util.byte2hex(sha.hash(bytes_text))

    util.writetxt(ECC_INPUT, text_hash)

    ''' ENCRYPT HASH MESSAGE '''
    # ecc.show_info()
    encode_hash = ecc_encoder.encode()
    encrypted_hash = ecc.encrypt(encode_hash)
    ecc_encoder.write_encrpyted(encrypted_hash)

    ''' MAKE SIGNATURE FILE '''
    text = util.readtxt(filename)
    signature = util.readtxt(ECC_RESULT)

    ''' SAVE SIGNATURE FILE '''
    if pisah:
        # only write signature to target
        util.writetxt(target, ''.join(signature))
        # util.writetxt(f"{DEMO_DIR}/signature.sgn", ''.join(signature))
    else:
        # only write message+signature (signed file) to target
        ''' SAVE SIGNED FILE '''
        text.append(BEGIN_SIGN + "\n")
        for x in signature:
            text.append(x)
        text.append("\n" + END_SIGN)

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
    signature = split[1].split("\n" + END_SIGN)[0]

    ''' GET HASH MESSAGE '''
    bytes_msg = msg.encode('utf-8')
    hash_msg = util.byte2hex(sha.hash(bytes_msg))

    ''' GET DECRYPTED SIGNATURE '''
    util.writetxt(ECC_RESULT, signature)
    ret = ecc_encoder.read_encrypted()
    points = ecc.decrypt(ret)
    decrypted_sign = ecc_encoder.decode(points)
    
    print("  " + hash_msg)
    print("  " + decrypted_sign)
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
    util.writetxt(ECC_RESULT, ''.join(signature))
    ret = ecc_encoder.read_encrypted()
    points = ecc.decrypt(ret)
    decrypted_sign = ecc_encoder.decode(points)

    print("  " + hash_msg)
    print("  " + decrypted_sign)
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

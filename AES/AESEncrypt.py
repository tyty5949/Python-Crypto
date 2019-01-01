from Crypto.Cipher import AES
import sys
import codecs
import hashlib
import time


def pkcs7_pad(data, size):
    byte = size - len(data) % size
    if byte == 16:
        return data
    print("PKCS7 - Adding " + str(byte) + " bytes of padding.")
    out = bytearray(data)
    for i in range(0, byte):
        out.append(byte)
    return out


def encrypt(plaintext, key, mode="ecb", iv=None):
    print("---------------------------------------")
    print("AES ENCRYPTION")
    print("Using " + str(len(plaintext)) + " bytes of plaintext.")
    # Pad data to make it AES compliant
    plaintext_out = pkcs7_pad(plaintext, 16)

    # Pad key
    print("Padding key to 16 bytes...")
    key = pkcs7_pad(key, 16)

    # Generate IV if necessary
    if mode.lower() == "cbc" and iv is None:
        print("Generating IV from md5 of key...")
        iv = hashlib.md5(key).digest()[:16]

    # Setup cipher
    cipher = None
    if mode.lower() == "cbc":
        cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
        print("Encrypting with CBC...")
    elif mode.lower() == "ecb":
        cipher = AES.new(bytes(key), AES.MODE_ECB)
        print("Encrypting with ECB...")
    else:
        print("Requires supported cipher type!")
        return None

    # Do encryption
    ciphertext = cipher.encrypt(bytes(plaintext_out))
    print("---------------------------------------")

    return ciphertext


if __name__ == "__main__":
    # Verify command line arguments
    if len(sys.argv) < 4:
        print("usage: AESEncrypt.py <in_file> <out_file> <key> [-iv <iv>] [-b64] [-ecb|-cbc]")
        sys.exit(-1)

    # Start timer
    start = time.time()

    # Read input file
    with open(sys.argv[1], "rb") as input_file:
        plaintext = input_file.read()

    # Read args
    key = sys.argv[3].encode()
    mode = "cbc"
    iv = None
    if "-ecb" in sys.argv:
        mode = "ecb"
    if "-iv" in sys.argv:
        iv = sys.argv[sys.argv.index("-iv")+1]
        iv.encode()

    # Do encryption
    ciphertext = encrypt(plaintext, key, mode, iv)

    # Encode to base64 if necessary
    if "-b64" in sys.argv:
        ciphertext = codecs.encode(ciphertext, "base64")

    # Write output
    with open(sys.argv[2], "wb") as output_file:
        plaintext = output_file.write(ciphertext)

    print("Done. Took " + str(time.time() - start) + " seconds")

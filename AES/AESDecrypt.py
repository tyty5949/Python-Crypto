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


def decrypt(ciphertext, key, mode="ecb", iv=None):
    print("---------------------------------------")
    print("AES DECRYPTION")
    print("Using " + str(len(ciphertext)) + " bytes of ciphertext.")

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
        print("Using IV " + str(iv))
        cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
        print("Decrypting with CBC...")
    elif mode.lower() == "ecb":
        cipher = AES.new(bytes(key), AES.MODE_ECB)
        print("Decrypting with ECB...")
    else:
        print("Requires supported cipher type!")
        return None

    # Do encryption
    plaintext = cipher.decrypt(bytes(ciphertext))
    print("---------------------------------------")

    return plaintext


if __name__ == "__main__":
    # Verify command line arguments
    if len(sys.argv) < 4:
        print("usage: AESDecrypt.py <in_file> <out_file> <key> [-iv <iv>] [-b64] [-ecb|-cbc]")
        sys.exit(-1)

    # Start timer
    start = time.time()

    # Read input file
    with open(sys.argv[1], "rb") as input_file:
        ciphertext = input_file.read()

    # Decode from base64 if necessary
    if "-b64" in sys.argv:
        ciphertext = codecs.decode(ciphertext, "base64")

    # Read args
    key = sys.argv[3].encode()
    mode = "ecb"
    iv = None
    if "-cbc" in sys.argv:
        mode = "cbc"
    if "-iv" in sys.argv:
        iv = sys.argv[sys.argv.index("-iv")+1]
        iv.encode()

    # Do encryption
    plaintext = decrypt(ciphertext, key, mode, iv)

    # Write output
    with open(sys.argv[2], "wb") as output_file:
        output_file.write(plaintext)

    print("Done. Took " + str(time.time() - start) + " seconds")

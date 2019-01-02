"""
Solution for CryptoPals Challenge 13
1/1/19


Description:
The code provides three main sets of functions...
  1) Provides AES ECB encryption functionality
  2) Provides example "real world" library functions
  3) Demonstrates an example of "cut-and-paste" attack


Writeup:
This challenge was about learning how to perform a simple example
of a cut-and-paste attack. The attacker only has access to the
library function which generates ciphertext, the ciphertexts
themselves, and can give the ciphertext to the parsing function.
In order for the attack to succeed, the attacker needs to have
a profile of "role=admin" when parsed.

Note how this attack can be done without the attacker ever needing
to decrypt the encryption or figure out the encryption key.

The first thing we need to do is to find out the length of the
plaintext so that we can essentially have it overflow the word
"user" into the last block. We will replace the ciphertext block
containing "user" with a ciphertext block containing "admin" we
will generate later.

In order to start that process, we must first identify how long
the email must be in order to get the ciphertext to overflow
just the word "user" into the final block. We can do this by
incrementally increasing the length of the supplied email.

0)
    <----Block 1--->  <----Block 2--->
    email=&uid=25&ro  le=userPPPPPPPPP
         |                   |_______|
         0                       9
1)
    <----Block 1--->  <----Block 2--->
    email=X&uid=25&r  ole=userPPPPPPPP
          |                   |______|
          1                      8
1)
    <----Block 1--->  <----Block 2--->
    email=XX&uid=25&  role=userPPPPPPP
          \/                   |_____|
.         2                       7
.
.

9)
    <----Block 1--->  <----Block 2--->  <----Block 3--->
    email=XXXXXXXXX&  uid=25&role=user  PPPPPPPPPPPPPPPP
          |_______|   |______________|  |______________|
              9             full               16

We can detect when Block 3 is created since the overall length
of the ciphertext will increase by 16 since PCKS7 padding
standards dictate that when the last block becomes full of
plaintext, an entire block of padding is added after it. Since that
happens when the length of the email is 9, then we know if we
increase the length of the email by 4, the only thing in Block 3
will be the plain text "user" followed by padding. We will call
this the base plaintext or base ciphertext.

<----Block 1--->  <----Block 2--->  <----Block 3--->
email=XXXXXXXXXX  XXX&uid=25&role=  userPPPPPPPPPPPP
      |_____________|               |______________|
            9+4                        exploitable

encrypts to

<----Block 1--->  <----Block 2--->  <----Block 3--->
B1B1B1B1B1B1B1B1  B2B2B2B2B2B2B2B2  B3B3B3B3B3B3B3B3
                                    |______________|
                                       exploitable

Knowing that the AES ECB algorithm is going to encrypt the plaintext
by splitting it up into blocks of 16 bytes, we can craft a malicious
email that will allow us create an entire encrypted block of our
choosing. We do that generating an email which will fill up the entire
first block leaving us to append what ever we want until we fill
up the second block.

<----Block 1--->  <----Block 2--->  <----Block 3--->  ...
email=XXXXXXXXXX  adminPPPPPPPPPPP  &uid=25&role=use  ...
|______________|  |______________|
 strategic full     what we need
encrypts to

<----Block 1--->  <----Block 2--->  <----Block 3--->
E1E1E1E1E1E1E1E1  E2E2E2E2E2E2E2E2  E3E3E3E3E3E3E3E3
                  |______________|
                    what we need

In this case we generate the email XXXXXXXXXXadminPPPPPPPPPPP where
we set P to the correct byte for the padding of a final block. This
effectively gets us a block we can "cut-and-paste" replacing the
final block of the base ciphertext we generated above. The final
ciphertext will become...

<----Block 1--->  <----Block 2--->  <----Block 3--->
B1B1B1B1B1B1B1B1  B2B2B2B2B2B2B2B2  E2E2E2E2E2E2E2E2
                                    |______________|
                                     cut-and-pasted
decrypts to

<----Block 1--->  <----Block 2--->  <----Block 3--->
email=XXXXXXXXXX  XXX&uid=25&role=  adminPPPPPPPPPPP
                                    |______________|
                                        injected

which when parsed by the internal library will give us a
profile with "role=admin" effectively breaking the system.

References:
https://cryptopals.com/sets/2/challenges/13
https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)
"""
import random
from Crypto.Cipher import AES

"""
------------------------------
    Encryption Functions
------------------------------
"""


def pcks7_pad(s: bytes, l: int) -> bytes:
    """
    Pads the given string to the specified length. Follows PCKS7 standard.

    :param s:   the string to pad
    :param l:   the number of bytes to pad to
    :return:    the given string padded to the given length
    """
    return s + bytes((l - len(s) % l) * chr(l - len(s) % l), "utf-8")


def pcks7_unpad(s: bytes) -> bytes:
    """
    Un-pads the given string by removing the padding bytes. Follows
    PCKS7 standard.

    :param s:
    :return:
    """
    return s[:-ord(s[len(s) - 1:])]


def aes_ecb_encrypt(plaintext: bytes) -> bytes:
    """
    Encrypts the given plaintext into ciphertext using the given key using
    AES ECB mode. The plaintext is first padded to 16 bytes using the PCKS7
    standard.

    :param plaintext:   the plaintext to encrypt
    :return:            the encrypted plaintext, ciphertext
    """
    global key
    plaintext = pcks7_pad(plaintext, 16)
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    return cipher.encrypt(bytes(plaintext))


def aes_ecb_decrypt(ciphertext: bytes) -> bytes:
    """
    Decrypts the given ciphertext into plaintext using the given key using
    AES ECB mode. The ciphertext is first decrypted then the plaintext
    un-padded using the PCKS7 standard, effectively removing all padding.

    :param ciphertext:  the encrypted text to be decrypted
    :return:            the decrypted ciphertext, plaintext
    """
    global key
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    plaintext = cipher.decrypt(bytes(ciphertext))
    return pcks7_unpad(plaintext)


"""
------------------------------
      Library Functions
------------------------------
"""


def parse_argument_string(argstring: str) -> dict:
    """
    "Pretend" library function which converts the given argument string
    of form x=y&z=w to a dictionary of form {x:y, z:w}

    :param argstring:
    :return:
    """
    paramstrings = argstring.split("&")
    params = {}
    for paramstring in paramstrings:
        paramset = paramstring.split("=")
        params[paramset[0]] = paramset[1]
    return params


def create_argument_string(args: dict) -> str:
    """
    "Pretend" library function which creates an argument string from the
    given dictionary.
    Given dictionary is in form {x:y, z:w}
    Returned parameter string in form x=y&z=w

    :param args:    the given dictionary to be converted to argument string format
    :return:        the dictionary in argument string format
    """
    argstring = ""
    first = True
    for arg in args.items():
        if not first:
            argstring += "&"
        first = False
        argstring += str(arg[0]) + "=" + str(arg[1])
    return argstring


def profile_for(email: str) -> str:
    """
    "Pretend" library function which creates a profile for the given email
    Sanitizes input by removing all given '&' and '=' symbols
    Email is used for profile, uid is random between 10-25, and role is set to user
    Profile is returned as a string in x=y&z=w format

    :param email:   the email which is used for the profile
    :return:        the final created profile formatted as a parameter string
    """
    email = email.replace("&", "")
    email = email.replace("=", "")
    profile = {"email": email, "uid": random.randrange(10, 25), "role": "user"}
    return create_argument_string(profile)


def profile_for_enrypted(email: str) -> bytes:
    """
    Combines profile_for and encryption functions into a single "pretend"
    library function which generates an encrypted profile for the given
    email.
    This is our "oracle" for our attack.

    :param email:   the email which is used for the profile
    :return:        the ciphertext for the encrypted profile argument string
    """
    return aes_ecb_encrypt(profile_for(email).encode())


"""
------------------------------
         Main Logic
------------------------------
"""

# -- Server side --
# Generate random encryption key
key = bytearray()
for i in range(0, 16):
    key.append(random.randrange(33, 127))
print("\nServer generated:")
print("  Encryption key: " + key.decode())

# -- Attacker side --
print("\nAttacker knows:")
print("  profile_for_encrypted(email) function")
print("  ciphertexts from oracle")

# Perform cut-and-paste attack
print("\nPerforming cut-and-paste attack...")

# Determine length of email necessary to fill 2nd to last block
emptyciphertext = profile_for_enrypted("")
emaillength = -1
ciphertext = bytearray(len(emptyciphertext))
# While padding not overflowed to new block
while len(emptyciphertext) == len(ciphertext):
    emaillength += 1
    email = "".join(["A" for i in range(0, emaillength)])
    ciphertext = profile_for_enrypted(email)
print("Found length of email necessary to fill to last block: " + str(emaillength))

# Generate base ciphertext by overflowing the word "user" into final block
baseoffset = len("user")
email = "".join(["A" for i in range(0, emaillength+baseoffset)])
baseciphertext = profile_for_enrypted(email)

# Generate admin ciphertext block
emailoffset = len("email=")
email = "".join(["A" for i in range(0, 16-emailoffset)])
email += "admin"
email = bytearray(email.encode())
# Add in pretend padding bytes
padding = 16-len("admin")
for i in range(0, padding):
    email.append(padding)
print("Created malicious email: " + str(email))
adminciphertext = profile_for_enrypted(email.decode())

# Grab admin block
adminblock = adminciphertext[16:32]  # block 2

# Create forged ciphertext
# Remove last block from base ciphertext
baseciphertext = baseciphertext[:len(baseciphertext)-16]
# cut-and-paste generated admin block
ciphertext = baseciphertext + adminblock
print("Created malicious ciphertext: " + str(ciphertext))

# -- Server side --
# Decrypt the encrypted profile string
print("\nServer side:")
plaintext = aes_ecb_decrypt(ciphertext)
print("  Decrypted to: " + str(plaintext))

# Decode decrypted argument string
print("  Decoded to:   " + str(parse_argument_string(plaintext.decode())))

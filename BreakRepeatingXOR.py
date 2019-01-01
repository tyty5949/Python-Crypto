"""
Script which attempts to bruteforce a repeating xor encrypted
text message.

Algorithm from https://cryptopals.com/sets/1/challenges/6
"""

import base64

keysize_to_use = 0
file = "a.out"


def score_bytes(input_bytes):
    """ Determines confidence in how likely the input_bytes are english using frequency analysis """
    """ Score goes up as the text appears has higher amounts of likely english """
    # https://en.wikipedia.org/wiki/Letter_frequency
    characterfrequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253, 'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025, 'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056, 'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13702
    }

    sum = 0
    for byte in input_bytes.lower():
        sum += characterfrequencies.get(chr(byte), 0)
    return sum


def repeating_xor_bytes(cipher_text, key):
    """xor cipherText with repeating key"""
    xor = bytearray(len(cipher_text))
    for i in range(0, len(cipher_text)):
        xor[i] = cipher_text[i] ^ key[i % len(key)]
    return xor


def single_xor_bytes(cipher_text, key):
    """xor cipherText with single byte key"""
    xor = bytearray(len(cipher_text))
    for i in range(0, len(cipher_text)):
        xor[i] = cipher_text[i] ^ key
    return xor


def hamming_distance(s, t):
    """ Calculate hamming distance between two byte arrays """
    s1 = ''.join([format(i, '08b') for i in s])
    s2 = ''.join([format(i, '08b') for i in t])
    return sum(c1 != c2 for c1, c2 in zip(s1, s2))


# Read in file
with open(file, "rb") as input_file:
    # ciphertext = base64.b64decode(input_file.read())
    ciphertext = input_file.read()

# Find possible keysizes
keysizeresults = {}
for keysize in range(2, 41):
    # Split into blocks
    blocks = [ciphertext[i:i + keysize] for i in range(0, len(ciphertext) - (len(ciphertext) % keysize), keysize)]

    # Calculate normalized score of blocks
    distances = []
    while len(blocks) >= 2:
        distances.append(hamming_distance(blocks[0], blocks[1]) / keysize)
        blocks.remove(blocks[0])
        blocks.remove(blocks[0])

    # Average score
    score = sum(distances) / len(distances)

    # Record score
    keysizeresults[keysize] = score

# Find most likely keysizes
keysizeresults = sorted(keysizeresults.items(), key=lambda kv: kv[1])

# Use most likely keysize
keysize = keysizeresults[keysize_to_use][0]
print("Using possible keysize:")
print(keysize)

# Split into blocks
blocks = [ciphertext[i:i + keysize] for i in range(0, len(ciphertext) - (len(ciphertext) % keysize), keysize)]

# Create transpose blocks
transposeblocks = []
for i in range(0, keysize):
    block = bytearray()
    for j in range(0, len(blocks)):
        block.append(blocks[j][i])
    transposeblocks.append(block)

# Bruteforce each character in key using transpose blocks
possiblekey = bytearray()
for block in transposeblocks:
    results = {}
    for i in range(32, 128):  # ASCII range
        decrypted_bytes = single_xor_bytes(block, i)
        results[i] = score_bytes(decrypted_bytes)
    results = sorted(results.items(), key=lambda kv: kv[1], reverse=True)
    possiblekey.append(results[0][0])

# Found possible key
print("\nFound possible key:")
print(possiblekey.decode())

# Decode message
decoded = repeating_xor_bytes(ciphertext, possiblekey)
print("\nDecoded message to:")
print(decoded.decode("utf-8", "replace"))

"""
This Python script encrypts a file with with a repeating XOR cipher.

Usage: python RepeatingXORFile.py <key> <input_file> <output_file>
    <key>          The key to encrypt/decrypt with.
    <input_file>   Specifies the input file.
    <output_file>  Specifies the output file.
"""

import sys

key = None
input_path = None
output_path = None


def print_usage():
    """ Function to print the usage statement """
    print("Usage: python RepeatingXORFile.py <key> <input_file> <output_file>")
    print("    <key>          The key to encrypt/decrypt with.")
    print("    <input_file>   Specifies the input file.")
    print("    <output_file>  Specifies the input file.")


def parse_arguments():
    """ Function to parse and verify the command line arguments """
    global mode
    global key
    global input_path
    global output_path
    if len(sys.argv) < 4:
        print_usage()
        sys.exit(-1)
    key = sys.argv[1]
    input_path = sys.argv[2]
    output_path = sys.argv[3]


def main():
    # Parse and verify arguments
    parse_arguments()

    # Open input and output file
    input_file = open(input_path, "rb")
    output_file = open(output_path, "wb")
    if input_file is None:
        print("Unable to open input file!")
        sys.exit(-3)
    if output_file is None:
        print("Unable to create output file!")
        sys.exit(-4)

    # Do XOR encryption/decryption for each byte in file
    key_bytes = bytes(key.encode("ascii"))
    count = 0
    byte = input_file.read(1)
    while byte:
        data = byte[0] ^ key_bytes[count % len(key)]
        output_file.write(bytes([data]))
        byte = input_file.read(1)
        count += 1

    # Close files
    input_file.close()
    output_file.close()


if __name__ == "__main__":
    """ Execute main function """
    main()

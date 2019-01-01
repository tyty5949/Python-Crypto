import sys
import codecs
import time


def score(ciphertext):
    # split into blocks of 16 with offsets 0:15
    score = 0

    print("     Progress")
    print("<---------------->")
    sys.stdout.write('-')
    sys.stdout.flush()

    # Loop over all offsets from 0-15
    for offset in range(0, 16):
        # Split up into blocks of size 16 with given offset
        blocks = [ciphertext[i + offset:i + 16 + offset] for i in range(0, len(ciphertext), 16)]

        # Count number of repetition of blocks that occur
        repetitions = []
        for block in blocks:
            if block in repetitions:
                score += 1
            else:
                repetitions.append(block)
        sys.stdout.write('#')
        sys.stdout.flush()
    print("-")
    return score


if __name__ == "__main__":
    # Verify command line arguments
    if len(sys.argv) < 2:
        print("usage: ECBDetect.py <file_name> [-b64]")
        sys.exit(-1)

    # Start timer
    start = time.time()

    # Read in file
    with open(sys.argv[1], "rb") as input_file:
        ciphertext = input_file.read()

    # Convert from base64 if necessary
    if len(sys.argv) >= 3 and sys.argv[2] == "-b64":
        ciphertext = codecs.decode(ciphertext, "base64")
    print("Read in " + str(len(ciphertext)) + " bytes of ciphertext.")

    # Try to determine type
    score = score(ciphertext)
    print("Done. Took " + str(time.time() - start) + " seconds")

    # Print output
    print("\nPossibly encrypted with: ")
    if score >= 1:
        print("    ECB (" + str(score) + ")  found repetitions, more is better...")
    else:
        print("    CBC (0)  unable to find any repetitions...")

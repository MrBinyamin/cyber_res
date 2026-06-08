import numpy as np
import time

MODULO = 3329 #common prime modulus for LWE-based schemes
N = 4 #matrix size



def generate_keys():
    """create public and private keys for the LWE-based encryption scheme """
    A = np.random.randint(0, MODULO, (N, N))
    s = np.random.randint(-2, 3, size=(N, 1))
    e = np.random.randint(-1, 2, size=(N, 1))

    #calculate t = A * s + e (modulo) - public key component
    t = (np.matmul(A, s) + e) % MODULO
    return (A, t), s


def encrypt(public_key, message_bit):
    """encrypt a single bit using the public key"""
    A, t = public_key
    r = np.random.randint(-2, 3, size=(N, 1))
    e1 = np.random.randint(-1, 2, size=(N, 1))
    e2 = np.random.randint(-1, 2)

    #calculate u and v for the ciphertext
    u = (np.matmul(A.T, r) + e1) % MODULO
    v = (np.matmul(t.T, r) + e2 + (message_bit * (MODULO // 2))) % MODULO
    return u, v


def decrypt(ciphertext, private_key):
    """decrypt the ciphertext using the private key and return the original bit"""
    u, v = ciphertext
    s = private_key

    #cleaning the noise from the ciphertext to recover the message bit
    res = (v - np.matmul(s.T, u)) % MODULO

    #decide if the result corresponds to a 0 or 1 based on its position in the modulo range
    if (MODULO // 4) < res < (3 * MODULO // 4):
        return 1
    return 0



def encrypt_string(public_key, plain_text):
    """encrypt a full string by encrypting each character bit by bit and returning a list of ciphertexts"""
    ciphertext_list = []
    for char in plain_text:
        bits = format(ord(char), '08b')
        for bit in bits:
            cipher = encrypt(public_key, int(bit))
            ciphertext_list.append(cipher)
    return ciphertext_list


def decrypt_string(ciphertext_list, private_key):
    """decrypt a list of ciphertexts to recover the original string"""
    decrypted_bits = ""
    for cipher in ciphertext_list:
        bit = decrypt(cipher, private_key)
        decrypted_bits += str(bit)

    chars = []
    for i in range(0, len(decrypted_bits), 8):
        byte = decrypted_bits[i:i + 8]
        chars.append(chr(int(byte, 2)))
    return "".join(chars)



if __name__ == "__main__":
    #create keys
    pk, sk = generate_keys()

    #test encryption and decryption of a full string
    my_message = ("This is a larger test message to demonstrate the LWE-based encryption over multiple "
                  "characters: CyberProject2026 - Encryption demo. It includes numbers 12345, punctuation, and "
                  "mixed case to exercise the bitwise encoding and show expansion/benchmarking behavior.")
    print(f"--- Testing Full String Encryption ---")
    print(f"Original Text: {my_message}")

    #the encryption process will produce a list of ciphertexts, one for each bit of the message
    encrypted_data = encrypt_string(pk, my_message)
    print(f"Encrypted blocks: {len(encrypted_data)}")

    decrypted_result = decrypt_string(encrypted_data, sk)
    print(f"Decrypted Text: {decrypted_result}")

    #verify that the decrypted text matches the original message
    if my_message == decrypted_result:
        print("\n[SUCCESS] The message was recovered perfectly!")
    else:
        print("\n[FAILED] There was an error in the recovery process.")


def run_performance_benchmarking(pk, message):
    """benchmark the performance of encryption and decryption for the given message and keys"""
    print(f"\n--- Performance Analysis ---")

    start_enc = time.time()
    encrypted_data = encrypt_string(pk, message)
    end_enc = time.time()
    enc_time = end_enc - start_enc

    start_dec = time.time()
    decrypted_result = decrypt_string(encrypted_data, sk)
    end_dec = time.time()
    dec_time = end_dec - start_dec

    original_size = len(message) * 8
    cipher_elements = len(encrypted_data) * (N + 1)

    print(f"Total Encryption Time: {enc_time:.4f} seconds")
    print(f"Total Decryption Time: {dec_time:.4f} seconds")
    print(f"Average time per character: {enc_time / len(message):.5f} seconds")
    print(f"Data Expansion Factor: {cipher_elements / len(message):.1f}x (Lattice overhead)")


run_performance_benchmarking(pk, my_message)


def run_string_security_tests(pk, original_text):
    """perform security tests by tampering with the ciphertext and using wrong keys to ensure the system's robustness"""
    print(f"\n--- String Security & Negative Tests ---")

    encrypted_data = encrypt_string(pk, original_text)


    u_orig, v_orig = encrypted_data[0]
    tampered_v = (v_orig + (MODULO // 2)) % MODULO
    encrypted_data[0] = (u_orig, tampered_v)

    decrypted_text = decrypt_string(encrypted_data, sk)

    if decrypted_text != original_text:
        print(f"[PASSED] Tampering Test: Changing one bit corrupted the message (Security verified).")
        print(f"Resulting string (corrupted): {decrypted_text}")
    else:
        print(f"[FAILED] Tampering Test: The system is too stable, it ignored the change.")


    _, wrong_sk = generate_keys()
    decrypted_with_wrong_key = decrypt_string(encrypt_string(pk, original_text), wrong_sk)

    if decrypted_with_wrong_key != original_text:
        print(f"[PASSED] Invalid Key Test: Wrong private key could not recover the original text.")
    else:
        print(f"[FAILED] Invalid Key Test: Security breach! Wrong key decrypted the message.")


    empty_res = decrypt_string(encrypt_string(pk, ""), sk)
    if empty_res == "":
        print("[PASSED] Edge Case: Empty string handled correctly.")
run_string_security_tests(pk, my_message)


def benchmark_performance(public_key, private_key):
    """benchmark the encryption and decryption times for messages of varying lengths to analyze performance scaling"""
    test_messages = [
        "A",
        "Hello",
        "Cyber Security 2026"
    ]

    print(f"{'Message Length':<20} | {'Enc Time (s)':<15} | {'Dec Time (s)':<15}")
    print("-" * 55)

    for msg in test_messages:
        start_enc = time.time()
        cipher = encrypt_string(public_key, msg)
        end_enc = time.time()

        start_dec = time.time()
        decrypted = decrypt_string(cipher, private_key)
        end_dec = time.time()

        print(f"{len(msg):<20} | {end_enc - start_enc:<15.5f} | {end_dec - start_dec:<15.5f}")


pk, sk = generate_keys()
my_message = ("This is a larger test message to demonstrate the LWE-based encryption over multiple "
              "characters: CyberProject2026 - Encryption demo. It includes numbers 12345, punctuation, and "
              "mixed case to exercise the bitwise encoding and show expansion/benchmarking behavior.")
benchmark_performance(pk, sk)
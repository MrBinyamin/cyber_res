import numpy as np
import time

# --- 1. הגדרת פרמטרים (על פי תקן Kyber/ML-KEM בגרסה מופשטת) ---
MODULO = 3329  # המודולו הסטנדרטי [cite: 28]
N = 4  # ממד המטריצה (לצורכי הפרויקט הלימודי) [cite: 56]


# --- 2. פונקציות ליבת האלגוריתם ---

def generate_keys():
    """ייצור מפתח ציבורי ופרטי מבוסס Module-LWE [cite: 52, 58]"""
    A = np.random.randint(0, MODULO, (N, N))  # מטריצה ציבורית
    s = np.random.randint(-2, 3, size=(N, 1))  # מפתח פרטי (ווקטור סודי)
    e = np.random.randint(-1, 2, size=(N, 1))  # רעש (Error)

    # חישוב המפתח הציבורי: t = As + e
    t = (np.matmul(A, s) + e) % MODULO
    return (A, t), s


def encrypt(public_key, message_bit):
    """הצפנת ביט בודד (0 או 1) [cite: 58]"""
    A, t = public_key
    r = np.random.randint(-2, 3, size=(N, 1))
    e1 = np.random.randint(-1, 2, size=(N, 1))
    e2 = np.random.randint(-1, 2)

    # u = A^T * r + e1
    u = (np.matmul(A.T, r) + e1) % MODULO
    # v = t^T * r + e2 + (Message * MODULO/2)
    v = (np.matmul(t.T, r) + e2 + (message_bit * (MODULO // 2))) % MODULO
    return u, v


def decrypt(ciphertext, private_key):
    """פענוח ביט בודד בעזרת המפתח הפרטי [cite: 58, 60]"""
    u, v = ciphertext
    s = private_key

    # ניקוי הרעש: v - s^T * u
    res = (v - np.matmul(s.T, u)) % MODULO

    # החלטה: האם הערך קרוב יותר ל-0 או ל-MODULO/2
    if (MODULO // 4) < res < (3 * MODULO // 4):
        return 1
    return 0


# --- 3. פונקציות לטיפול בטקסט מלא (Arbitrary Message)  ---

def encrypt_string(public_key, plain_text):
    """הפיכת מחרוזת לרשימת צפנים קוונטיים"""
    ciphertext_list = []
    for char in plain_text:
        bits = format(ord(char), '08b')  # הפיכת תו ל-8 ביטים
        for bit in bits:
            cipher = encrypt(public_key, int(bit))
            ciphertext_list.append(cipher)
    return ciphertext_list


def decrypt_string(ciphertext_list, private_key):
    """פענוח רשימת צפנים חזרה למחרוזת טקסט"""
    decrypted_bits = ""
    for cipher in ciphertext_list:
        bit = decrypt(cipher, private_key)
        decrypted_bits += str(bit)

    chars = []
    for i in range(0, len(decrypted_bits), 8):
        byte = decrypted_bits[i:i + 8]
        chars.append(chr(int(byte, 2)))
    return "".join(chars)


# --- 4. הרצה ובדיקה ---

if __name__ == "__main__":
    # יצירת מפתחות (אליס)
    pk, sk = generate_keys()

    # הודעה לבדיקה
    my_message = "CyberProject2026"
    print(f"--- Testing Full String Encryption ---")
    print(f"Original Text: {my_message}")

    # הצפנה (בוב)
    encrypted_data = encrypt_string(pk, my_message)
    print(f"Encrypted blocks: {len(encrypted_data)}")

    # פענוח (אליס)
    decrypted_result = decrypt_string(encrypted_data, sk)
    print(f"Decrypted Text: {decrypted_result}")

    # בדיקת תקינות (Validation)
    if my_message == decrypted_result:
        print("\n[SUCCESS] The message was recovered perfectly!")
    else:
        print("\n[FAILED] There was an error in the recovery process.")


def run_performance_benchmarking(pk, message):
    print(f"\n--- Performance Analysis ---")

    # 1. מדידת זמן הצפנה
    start_enc = time.time()
    encrypted_data = encrypt_string(pk, message)
    end_enc = time.time()
    enc_time = end_enc - start_enc

    # 2. מדידת זמן פענוח
    start_dec = time.time()
    decrypted_result = decrypt_string(encrypted_data, sk)
    end_dec = time.time()
    dec_time = end_dec - start_dec

    # 3. ניתוח גדלים (Overhead)
    original_size = len(message) * 8  # גודל בביטים
    # כל בלוק צופן מורכב מ-u (וקטור בגודל N) ומ-v (ערך בודד)
    # במימוש שלנו כל מספר הוא integer
    cipher_elements = len(encrypted_data) * (N + 1)

    print(f"Total Encryption Time: {enc_time:.4f} seconds")
    print(f"Total Decryption Time: {dec_time:.4f} seconds")
    print(f"Average time per character: {enc_time / len(message):.5f} seconds")
    print(f"Data Expansion Factor: {cipher_elements / len(message):.1f}x (Lattice overhead)")


# הוסף את השורה הזו בסוף ה-if __name__ == "__main__":
run_performance_benchmarking(pk, my_message)


def run_string_security_tests(pk, original_text):
    print(f"\n--- String Security & Negative Tests ---")

    # 1. בדיקת שינוי תו בודד בצופן (Tampering Test)
    # אנחנו משנים את הצופן של התו הראשון כדי לראות אם הפענוח נהרס
    encrypted_data = encrypt_string(pk, original_text)

    # ניקח את הביט הראשון של התו הראשון ונשבש אותו
    u_orig, v_orig = encrypted_data[0]
    tampered_v = (v_orig + (MODULO // 2)) % MODULO
    encrypted_data[0] = (u_orig, tampered_v)

    decrypted_text = decrypt_string(encrypted_data, sk)

    if decrypted_text != original_text:
        print(f"[PASSED] Tampering Test: Changing one bit corrupted the message (Security verified).")
        print(f"Resulting string (corrupted): {decrypted_text}")
    else:
        print(f"[FAILED] Tampering Test: The system is too stable, it ignored the change.")

    # 2. בדיקת מפתח לא תואם (Invalid Key Test)
    # יצירת סט מפתחות חדש לגמרי וניסיון לפענח איתו את ההודעה של אליס
    _, wrong_sk = generate_keys()
    decrypted_with_wrong_key = decrypt_string(encrypt_string(pk, original_text), wrong_sk)

    if decrypted_with_wrong_key != original_text:
        print(f"[PASSED] Invalid Key Test: Wrong private key could not recover the original text.")
    else:
        print(f"[FAILED] Invalid Key Test: Security breach! Wrong key decrypted the message.")

    # 3. בדיקת מקרה קצה: מחרוזת ריקה (Empty String)
    # סעיף 4.4 דורש בדיקת Edge cases כמו empty messages
    empty_res = decrypt_string(encrypt_string(pk, ""), sk)
    if empty_res == "":
        print("[PASSED] Edge Case: Empty string handled correctly.")
run_string_security_tests(pk, my_message)


def benchmark_performance(public_key, private_key):  # וודא שזה private_key
    test_messages = [
        "A",
        "Hello",
        "Cyber Security 2026"
    ]

    print(f"{'Message Length':<20} | {'Enc Time (s)':<15} | {'Dec Time (s)':<15}")
    print("-" * 55)

    for msg in test_messages:
        # הצפנה
        start_enc = time.time()
        cipher = encrypt_string(public_key, msg)
        end_enc = time.time()

        # פענוח - וודא שאתה מעביר את private_key שקיבלת כפרמטר
        start_dec = time.time()
        decrypted = decrypt_string(cipher, private_key)
        end_dec = time.time()

        print(f"{len(msg):<20} | {end_enc - start_enc:<15.5f} | {end_dec - start_dec:<15.5f}")


# כשאתה קורא לפונקציה בסוף הקובץ:
pk, sk = generate_keys()  # sk הוא המפתח הפרטי (Secret Key)
my_message = "CyberProject2026"
benchmark_performance(pk, sk)  # תעביר את sk כאן
import numpy as np

# פרמטרים בסיסיים (גרסה מופשטת לצרכי לימוד)
MODULO = 3329  # הערך הסטנדרטי של Kyber
N = 4  # ממד המטריצה (במציאות הוא גדול בהרבה)


def generate_keys():
    # 1. יצירת מטריצה ציבורית אקראית A
    A = np.random.randint(0, MODULO, (N, N))

    # 2. יצירת מפתח פרטי s (ווקטור עם ערכים קטנים)
    s = np.random.randint(-2, 3, size=(N, 1))

    # 3. יצירת רעש e (שגיאה קטנה)
    e = np.random.randint(-1, 2, size=(N, 1))

    # 4. חישוב המפתח הציבורי: t = A*s + e
    t = (np.matmul(A, s) + e) % MODULO

    return (A, t), s  # (מפתח ציבורי), מפתח פרטי


# אליס מייצרת מפתחות
public_key, private_key = generate_keys()
A, t = public_key


def encrypt(public_key, message_bit):
    A, t = public_key

    # בוב בוחר ווקטור אקראי r ורעש e1, e2
    r = np.random.randint(-2, 3, size=(N, 1))
    e1 = np.random.randint(-1, 2, size=(N, 1))
    e2 = np.random.randint(-1, 2)

    # חישוב u = A_transpose * r + e1
    u = (np.matmul(A.T, r) + e1) % MODULO

    # חישוב v = t_transpose * r + e2 + (הודעה מוזזת)
    # אנחנו מזיזים את הביט (0 או 1) לחצי מגודל המודולו כדי שיהיה קל לזהות אותו ברעש
    v = (np.matmul(t.T, r) + e2 + (message_bit * (MODULO // 2))) % MODULO

    return u, v


# בוב מצפין את הביט '1'
message = 1
ciphertext = encrypt(public_key, message)


def decrypt(ciphertext, private_key):
    u, v = ciphertext
    s = private_key

    # חישוב הערך המקורב: v - s_transpose * u
    res = (v - np.matmul(s.T, u)) % MODULO

    # אם התוצאה קרובה יותר ל-MODULO/2, זה '1'. אם קרובה ל-0, זה '0'.
    if res > (MODULO // 4) and res < (3 * MODULO // 4):
        return 1
    else:
        return 0


# אליס מפענחת
decrypted_message = decrypt(ciphertext, private_key)
print(f"Original Message: {message}")
print(f"Decrypted Message: {decrypted_message}")


def run_tests():
    print("--- Starting Cryptographic Test Suite ---")

    # 1. בדיקת סבב מלא (Round-trip Test)
    # מוודא שהודעה לגיטימית עוברת את כל התהליך בהצלחה
    public_key, private_key = generate_keys()

    test_bits = [0, 1]
    round_trip_success = True
    for bit in test_bits:
        cipher = encrypt(public_key, bit)
        decrypted = decrypt(cipher, private_key)
        if decrypted != bit:
            round_trip_success = False
            print(f"[FAILED] Round-trip failed for bit {bit}")

    if round_trip_success:
        print("[PASSED] Round-trip: Messages encrypted and decrypted correctly.")

    # 2. בדיקה שלילית: מפתח לא נכון (Wrong Key Test)
    # מדמה מצב של תוקף שמנסה לפענח עם מפתח פרטי אחר
    _, wrong_private_key = generate_keys()
    cipher = encrypt(public_key, 1)
    decrypted = decrypt(cipher, wrong_private_key)

    if decrypted != 1:
        print("[PASSED] Negative Test: Wrong key failed to decrypt (as expected).")
    else:
        print("[WARNING] Negative Test: Decryption with wrong key accidentally succeeded.")

    # 3. בדיקה שלילית: שינוי הצופן (Tampered Ciphertext)
    # מדמה תוקף שמשנה את המידע המוצפן בדרך (Malleability attack)
    u, v = encrypt(public_key, 1)
    # שינוי משמעותי בצופן - הוספת רעש חזק ל-v
    tampered_v = (v + (MODULO // 2)) % MODULO
    tampered_cipher = (u, tampered_v)

    decrypted_tampered = decrypt(tampered_cipher, private_key)
    if decrypted_tampered != 1:
        print("[PASSED] Negative Test: Tampered ciphertext resulted in incorrect decryption.")
    else:
        print("[FAILED] Negative Test: Algorithm was too resistant to tampering!")

    # 4. בדיקת עקביות (Consistency)
    # מוודא שהרנדומליות של בוב לא שוברת את הפענוח של אליס
    consistency_passed = True
    for _ in range(100):
        c = encrypt(public_key, 0)
        if decrypt(c, private_key) != 0:
            consistency_passed = False
            break

    if consistency_passed:
        print("[PASSED] Consistency: 100 random encryptions decrypted successfully.")


# הרצת הבדיקות
run_tests()
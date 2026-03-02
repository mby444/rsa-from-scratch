"""
Tugas Kriptografi: Implementasi Algoritma RSA dari Nol
Format: Ciphertext sebagai Hexadecimal String
"""

def is_prime(n: int) -> bool:
    """Mengecek apakah n adalah bilangan prima menggunakan algoritma 6k +/- 1."""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0: return False
        i += 6
    return True

def gcd(a: int, b: int) -> int:
    """Menghitung nilai pembagi terbesar (Greatest Common Divisor)."""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Algoritma Euclidean Diperluas untuk mencari Modular Multiplicative Inverse.
    Mengembalikan (gcd, x, y) sedemikian sehingga ax + by = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def modular_exponentiation(base: int, exp: int, mod: int) -> int:
    """
    Menghitung (base^exp) % mod secara efisien (Square-and-Multiply).
    Menghindari overflow pada angka yang sangat besar.
    """
    result = 1
    base %= mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp //= 2
        base = (base * base) % mod
    return result

def get_modular_inverse(e: int, phi: int) -> int:
    """Menghitung nilai d (Private Key) menggunakan Modular Multiplicative Inverse."""
    gcd_val, x, _ = extended_gcd(e, phi)
    if gcd_val != 1:
        raise ValueError("Modular inverse tidak ditemukan! e dan phi harus relatif prima.")
    return x % phi

def generate_key_pair(p: int, q: int) -> tuple[tuple[int, int], tuple[int, int]]:
    """Membangkitkan pasangan kunci publik dan kunci privat."""
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("p dan q harus merupakan bilangan prima.")
    if p == q:
        raise ValueError("p dan q tidak boleh sama.")
        
    n = p * q
    phi = (p - 1) * (q - 1)

    # Memilih public exponent e
    e = 3
    while gcd(e, phi) != 1:
        e += 2
        
    d = get_modular_inverse(e, phi)
    return (e, n), (d, n)

def encrypt(plaintext: str, public_key: tuple[int, int]) -> str:
    """Mengenkripsi teks menjadi string hexadecimal yang dipisahkan spasi."""
    e, n = public_key
    # Proses: Teks -> ASCII (ord) -> ModPow -> Hex
    cipher_hex = [hex(modular_exponentiation(ord(char), e, n))[2:] for char in plaintext]
    return " ".join(cipher_hex)

def decrypt(ciphertext_hex: str, private_key: tuple[int, int]) -> str:
    """Mendekripsi string hexadecimal kembali menjadi teks asli."""
    d, n = private_key
    try:
        # Proses: Hex -> Int -> ModPow -> Karakter (chr)
        hex_parts = ciphertext_hex.split()
        decrypted_chars = [chr(modular_exponentiation(int(h, 16), d, n)) for h in hex_parts]
        return "".join(decrypted_chars)
    except ValueError:
        return "[!] Gagal mendekripsi: Format ciphertext tidak valid."

def main():
    print("="*40)
    print("        SISTEM KRIPTOGRAFI RSA     ")
    print("="*40)
    
    # Inisialisasi prima (Default: 61 dan 53)
    p, q = 61, 53 
    
    try:
        # 1. Key Generation
        pub_key, priv_key = generate_key_pair(p, q)
        print(f"[+] Modulus (n)   : {pub_key[1]}")
        print(f"[+] Kunci Publik e: {pub_key[0]}")
        print(f"[+] Kunci Privat d: {priv_key[0]}")

        # 2. Input
        message = input("\n[>] Masukkan pesan: ")
        if not message: return

        # 3. Encryption
        ciphertext = encrypt(message, pub_key)
        print(f"\n[🔒] Ciphertext (Hex): {ciphertext}")

        # 4. Decryption
        decrypted_msg = decrypt(ciphertext, priv_key)
        print(f"[🔓] Hasil Dekripsi  : {decrypted_msg}")
        
        # 5. Validation
        if message == decrypted_msg:
            print("\n✅ Verifikasi Sukses: Data utuh dan aman.")
            
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")

if __name__ == "__main__":
    main()
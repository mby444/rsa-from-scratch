"""
Tugas Kriptografi: Implementasi Algoritma RSA dari Nol
"""

# ==========================================
# PART 1: MATHEMATICAL UTILITIES
# ==========================================

def is_prime(n: int) -> bool:
    """Mengecek apakah n bilangan prima (Efficiency: O(sqrt(n)))."""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0: return False
        i += 6
    return True

def get_gcd(a: int, b: int) -> int:
    """Menghitung Greatest Common Divisor (GCD)."""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b: int) -> tuple:
    """
    Extended Euclidean Algorithm untuk mencari Modular Inverse.
    Digunakan untuk menghitung Private Key (d).
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def modular_pow(base: int, exp: int, mod: int) -> int:
    """
    Menghitung (base^exp) % mod menggunakan Square-and-Multiply.
    Sangat efisien untuk menangani angka besar.
    """
    result = 1
    base %= mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp //= 2
        base = (base * base) % mod
    return result

# ==========================================
# PART 2: CORE RSA LOGIC
# ==========================================

def generate_keys(p: int, q: int):
    """Membangkitkan pasangan kunci (public_key, private_key)."""
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("P dan Q harus bilangan prima!")
    if p == q:
        raise ValueError("P dan Q tidak boleh sama!")
    
    n = p * q
    phi = (p - 1) * (q - 1)

    # Memilih e (Public Exponent)
    e = 3
    while get_gcd(e, phi) != 1:
        e += 2
        
    # Menghitung d (Private Exponent)
    gcd_val, x, _ = extended_gcd(e, phi)
    d = x % phi
    
    return (e, n), (d, n)

def encrypt_to_hex(message: str, public_key: tuple) -> str:
    """Mengubah teks menjadi rangkaian string hexadecimal."""
    e, n = public_key
    hex_list = []
    
    for char in message:
        m = ord(char)                # Karakter -> ASCII
        c = modular_pow(m, e, n)     # Rumus: c = m^e mod n
        hex_list.append(hex(c)[2:])  # Simpan hasil dalam format hex
        
    return " ".join(hex_list)

def decrypt_from_hex(hex_str: str, private_key: tuple) -> str:
    """Mengubah rangkaian string hexadecimal kembali ke teks asli."""
    d, n = private_key
    hex_parts = hex_str.split()
    plain_text = ""
    
    for h in hex_parts:
        c = int(h, 16)               # Hex -> Decimal
        m = modular_pow(c, d, n)     # Rumus: m = c^d mod n
        plain_text += chr(m)         # ASCII -> Karakter
        
    return plain_text

# ==========================================
# PART 3: MAIN INTERFACE
# ==========================================

def main():
    print("="*50)
    print("       RSA CRYPTOSYSTEM DEMONSTRATION       ")
    print("="*50)
    
    # Nilai p dan q (Bisa diganti dengan prima lain)
    p, q = 61, 53 
    
    try:
        # 1. Key Generation
        pub_key, priv_key = generate_keys(p, q)
        print(f"[+] Modulus (n)     : {pub_key[1]}")
        print(f"[+] Public Key (e)  : {pub_key[0]}")
        print(f"[+] Private Key (d) : {priv_key[0]}")

        # 2. Input
        original_msg = input("\n[>] Masukkan pesan teks: ")
        if not original_msg: return

        # 3. Encryption
        ciphertext = encrypt_to_hex(original_msg, pub_key)
        print(f"\n[🔒] Ciphertext (Hex): {ciphertext}")

        # 4. Decryption
        decrypted_msg = decrypt_from_hex(ciphertext, priv_key)
        print(f"[🔓] Hasil Dekripsi  : {decrypted_msg}")
        
        # 5. Validation
        if original_msg == decrypted_msg:
            print("\n✅ STATUS: Berhasil! Pesan identik dengan aslinya.")

    except Exception as e:
        print(f"\n❌ ERROR: {e}")

if __name__ == "__main__":
    main()
"""
Tugas Kriptografi: Implementasi Algoritma RSA dari Nol
"""

def is_prime(n: int) -> bool:
    """Mengecek apakah angka n adalah bilangan prima (O(sqrt(n)))."""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0: return False
        i += 6
    return True

def gcd(a: int, b: int) -> int:
    """Menghitung Greatest Common Divisor menggunakan Algoritma Euclidean."""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b: int) -> tuple:
    """
    Algoritma Euclidean Diperluas untuk mencari koefisien Bezout (x, y).
    Digunakan untuk mencari Modular Multiplicative Inverse.
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def modular_exponentiation(base: int, exp: int, mod: int) -> int:
    """
    Menghitung (base^exp) % mod menggunakan metode Square-and-Multiply.
    Mencegah integer overflow dan sangat efisien secara memori.
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
    """Menghitung nilai d (Private Key) sebagai kebalikan modular dari e."""
    gcd_val, x, _ = extended_gcd(e, phi)
    if gcd_val != 1:
        raise ValueError("Modular inverse tidak ditemukan!")
    return x % phi

def generate_key_pair(p: int, q: int) -> tuple:
    """Menghasilkan pasangan Kunci Publik (e, n) dan Kunci Privat (d, n)."""
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Kedua angka p dan q harus bilangan prima.")
    
    n = p * q
    phi = (p - 1) * (q - 1)

    # Memilih e yang relatif prima terhadap phi
    # 65537 adalah nilai standar industri, namun kita cari yang terkecil untuk tugas
    e = 3
    while gcd(e, phi) != 1:
        e += 2
        
    d = get_modular_inverse(e, phi)
    return (e, n), (d, n)

def encrypt(plaintext: str, public_key: tuple) -> list:
    """Mengubah teks menjadi daftar angka terenkripsi (Ciphertext)."""
    e, n = public_key
    # ord(char) mengubah karakter menjadi angka ASCII
    return [modular_exponentiation(ord(char), e, n) for char in plaintext]

def decrypt(ciphertext: list, private_key: tuple) -> str:
    """Mengembalikan daftar angka menjadi teks asli (Plaintext)."""
    d, n = private_key
    # chr(num) mengubah angka ASCII kembali menjadi karakter
    chars = [chr(modular_exponentiation(num, d, n)) for num in ciphertext]
    return "".join(chars)

def main():
    print("=== PROGRAM KRIPTOGRAFI RSA (CLEAN CODE) ===")
    
    # Input Prima (Contoh: p=61, q=53 untuk Modulus 3233)
    p, q = 61, 53 
    
    try:
        # 1. Pembangkitan Kunci
        public_key, private_key = generate_key_pair(p, q)
        print(f"\n[🔑] Kunci Publik: {public_key}")
        print(f"[🔑] Kunci Privat: {private_key}")

        # 2. Input Pesan
        message = input("\n[📝] Masukkan pesan: ")

        # 3. Enkripsi
        secret_code = encrypt(message, public_key)
        print(f"[🔒] Ciphertext: {secret_code}")

        # 4. Dekripsi
        original_msg = decrypt(secret_code, private_key)
        print(f"[🔓] Hasil Dekripsi: {original_msg}")
        
        # Validasi
        if message == original_msg:
            print("\n✅ Verifikasi Berhasil: Pesan identik.")
            
    except Exception as err:
        print(f"\n❌ Terjadi Kesalahan: {err}")

if __name__ == "__main__":
    main()
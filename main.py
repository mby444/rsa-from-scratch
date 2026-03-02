def is_prime(n):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0: return False
        i += 6
    return True

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """
    Mengembalikan (gcd, x, y) sedemikian sehingga ax + by = gcd(a, b).
    Dalam RSA: a adalah 'e', b adalah 'phi_n'.
    Kita mencari 'x' yang merupakan modular inverse dari 'e'.
    """
    if a == 0:
        return b, 0, 1
    else:
        gcd, x1, y1 = extended_gcd(b % a, a)
        # Update x dan y menggunakan hasil rekursif
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

def power(base, exp, mod):
    """
    Menghitung (base^exp) % mod secara efisien.
    Sangat penting untuk enkripsi (M^e % n) dan dekripsi (C^d % n).
    """
    res = 1
    base = base % mod  # Pastikan base lebih kecil dari mod
    
    while exp > 0:
        # Jika exp ganjil, kalikan base dengan hasil
        if exp % 2 == 1:
            res = (res * base) % mod
            
        # exp harus menjadi genap sekarang
        exp = exp // 2
        base = (base * base) % mod
        
    return res

def get_e(phi_n):
    """
    Mencari nilai e yang relatif prima dengan phi_n.
    Biasanya dimulai dari angka kecil (seperti 3) untuk efisiensi.
    """
    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    e = 2
    while e < phi_n:
        if gcd(e, phi_n) == 1:
            return e
        e += 1
    return None

def get_d(e, phi_n):
    """
    Menghitung d menggunakan Extended Euclidean Algorithm.
    d adalah inverse dari e dalam modulo phi_n.
    """
    gcd, x, y = extended_gcd(e, phi_n)
    
    if gcd != 1:
        raise ValueError("Modular inverse tidak ada (e dan phi_n tidak relatif prima)")
    else:
        # x bisa saja negatif, maka kita harus mengubahnya ke positif
        # dengan cara (x % phi_n)
        return x % phi_n

def gen_key():
  p, q = 61, 53
  n = p * q
  phi_n = (p - 1) * (q - 1)
  e = get_e(phi_n)
  d = get_d(e, phi_n)
  return e, d, n

def encrypt(text, e, n):
  encrypted_text = []

  for ch in text:
    c = power(ord(ch), e, n)
    encrypted_text.append(c)

  return encrypted_text

def decrypt(ciphertext, d, n):
  decrypted_text = ""

  for num in ciphertext:
    m = power(num, d, n)
    decrypted_text += chr(m)

  return decrypted_text

def main():
  user_input = input("Masukkan teks: ")
  e, d, n = gen_key()
  ciphertext = encrypt(user_input, e, n)
  print("Cipertext:", ciphertext)
  text = decrypt(ciphertext, d, n)
  print("Decrypted text:", text)

if __name__ == "__main__":
  main()
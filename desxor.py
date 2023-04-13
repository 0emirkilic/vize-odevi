from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib


def des_encrypt(text, key):
    # CBC modunda kullanmak için rastgele bir IV üret
    iv = get_random_bytes(DES.block_size)

    # anahtar türetmek için SHA256 kullan
    key = hashlib.sha256(key.encode()).digest()[:DES.block_size]

    # DES algoritması ile metni şifrele
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    ciphertext = cipher.encrypt(pad(text.encode(), DES.block_size))

    # IV ve şifreli metni birleştir
    result = iv + ciphertext

    return result


def des_decrypt(ciphertext, key):
    # IV ve şifreli metni ayır
    iv = ciphertext[:DES.block_size]
    ciphertext = ciphertext[DES.block_size:]

    # anahtar türetmek için SHA256 kullan
    key = hashlib.sha256(key.encode()).digest()[:DES.block_size]

    # DES algoritması ile şifreli metni çöz
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)

    return plaintext.decode()


# kullanıcıdan metin ve anahtar iste
text = input("Şifrelenecek metni girin: ")
key = input("Anahtar girin: ")

# metni şifrele ve şifreli metni ekrana yazdır
ciphertext = des_encrypt(text, key)
print("Şifreli metin: " + ciphertext.hex())

# şifreli metni çöz ve orijinal metni ekrana yazdır
plaintext = des_decrypt(ciphertext, key)
print("Çözülmüş metin: " + plaintext)

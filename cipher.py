import hashlib
from Crypto.Cipher import AES
from Crypto import Random


class Cryptography:

    def __init__(raw,key): #Ensure a standard key size of length 32
        raw.key=hashlib.sha256(key.encode("utf-8")).digest()

    def _pad(raw,message): #Pads a message by appending null bytes at the end
        if type(message) is not bytes:
            message=message.encode("utf-8")
        while len(message)%AES.block_size:
            message+=b'\0'
        return message
    
    def _unpad(raw,message): #Remove null bytes in a message added for padding
        return message.replace(b'\0',b'')   
    
    def encrypt(raw,message): #Encrypts a message using AES,CBC mode,returns initialization vector+ciphertext
        plaintext=raw._pad(message)
        iv=Random.new().read(AES.block_size)
        cipher=AES.new(raw.key,AES.MODE_CBC,iv)
        ciphertext=cipher.encrypt(plaintext)
        return iv+ciphertext

    def decrypt(raw,ciphertext): #Takes in an encrypted message and returns the decrypted version,it extracts iv from the ciphertext
        iv=ciphertext[:AES.block_size]
        ciphertext=ciphertext[AES.block_size:]
        cipher=AES.new(raw.key,AES.MODE_CBC,iv)
        plaintext=cipher.decrypt(ciphertext)
        return raw._unpad(plaintext).decode("utf-8")


message="Break the digital world"
key="Itshouldbe16letters"
aes_cipher=Cryptography(key)

encrypted_message=aes_cipher.encrypt(message) #Encrypt the message and store the encrypted message inside the output file
with open("output",'wb') as fd:
    fd.write(encrypted_message)

with open("output",'rb') as fd: #Open the output file containing an encrypted message,perfom decryption and write it to screen
    cipher_text=fd.read()
decrypted_message=aes_cipher.decrypt(cipher_text)


print(f"Encrypted: {encrypted_message}")
print(f"Decrypted: {decrypted_message}")

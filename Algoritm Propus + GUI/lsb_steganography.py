"""              Algoritmul LSB Propus              """
# Biblioteci
import os         
import binascii
import pbkdf2
import pyaes
import hashlib
import random
import numpy as np
from PIL import Image
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from custom_exceptions import *







########################################      CRIPTARE + DECRIPTARE MESAJ
# https://cryptobook.nakov.com/symmetric-key-ciphers/aes-encrypt-decrypt-examples
# trebuie să fie aceleași și pt criptare și pt decriptare
passwordSalt = b'\\`\xd6\xdaB\x03\xdd\xd4z\xb6p\xe8O\xf0\xa8\xc0'
iv = 12276418801510358845029257473125458269416880639997527613362129559241916371076
def encrypt(text, parola):
    """
        Derives a 256-bit key using the PBKDF2 key derivation algorithm from the password. It uses a random 
        password derivation salt (128-bit). This salt should be stored in the output, together with the ciphertext, 
        because without it the decryption key cannot be derived again and the decryption will be impossible.
        The derived key consists of 64 hex digits (32 bytes), which represents a 256-bit integer number.
    """
    key = pbkdf2.PBKDF2(parola, passwordSalt).read(32)  
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    cipherByte = aes.encrypt(text)
    return binascii.hexlify(cipherByte).decode('utf-8')   # hex digits

def decrypt(text, parola):
    res = bytes(text, 'utf-8')
    cipherByte = binascii.unhexlify(res)
    key = pbkdf2.PBKDF2(parola, passwordSalt).read(32)
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    originalByte = aes.decrypt(cipherByte)
    return originalByte.decode('utf-8')





###################################################     CRIPTARE + DECRIPTARE FIȘIER PIXELI
# https://www.novixys.com/blog/using-aes-encryption-decryption-python-pycrypto/
def encrypt_file(key, in_filename, out_filename=None, chunksize=64 * 1024):
    if not out_filename:
        out_filename = in_filename + '.enc'
    iv = get_random_bytes(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename, out_filename=None, chunksize=24 * 1024):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)





# Funcție care transformă orice tip de dată în binar
def textToBinary(text):
    binar = list(format(c, '08b') for c in bytearray(text.encode('latin-1')))
    return binar


def PixeliRandom(width, height, lenEncodedMessage):
    new = []
    Pixeli = []
    for i in range(width * height):
        new.append(i)
    for i in range(len(new) - 1, 0, -1):
        j = random.randint(0, i + 1)
        new[i], new[j] = new[j], new[i]
    for i in range(lenEncodedMessage * 3):
        Pixeli.append(new[i])
    vectorPixeli = np.array(Pixeli)
    np.savetxt("pixeliSecventa.txt", vectorPixeli, delimiter="\t")
    return Pixeli


def encodeAux(imgAux, encodedMessage, output_filepath, passwordPixels, progressBar): 
    width, height = imgAux.size
    # creez secvența de pixeli amestecați
    Pixeli = PixeliRandom(width, height, len(encodedMessage))
    textB = textToBinary(encodedMessage)  
    dr = 0
    
    progress = 0
    total_bits = 32 + len(encodedMessage) * 7
    progress_fraction = 1 / total_bits
    for i in range(0, len(encodedMessage) * 3, 3):
        dc = 0
        for j in range(0, 3):
            rr = Pixeli[i + j] // height
            rc = Pixeli[i + j] % height
            rgb = imgAux.getpixel((rr, rc))
            value = []
            idx = 0
            for k in rgb:
                if (k % 2 == 0 and textB[dr][dc] == '1'):
                    if (k == 0):
                        k += 1
                    else:
                        k -= 1
                if (k % 2 == 1 and textB[dr][dc] == '0'):
                    k -= 1
                value.append(k)
                idx += 1
                dc += 1
                
                if progressBar != None: 
                    progress += progress_fraction
                    progressBar.setValue(progress * 100)
                
                if (dc >= 8):
                    break
            if (dc >= 8):
                value.append(rgb[2])
            newrgb = (value[0], value[1], value[2])
            imgAux.putpixel((rr, rc), newrgb)
        dr += 1
     
    imgAux.save(output_filepath, str(output_filepath.split(".")[1].upper()))
    key = hashlib.sha256(passwordPixels.encode()).digest()
    encrypt_file(key, 'pixeliSecventa.txt')
         

# Funcția Principală pentru encodare
def encode(input_filepath, text, output_filepath, passwordPhoto, passwordPixels, progressBar = None): 
    image = Image.open(input_filepath, 'r') 
    encodedMessage = encrypt(text, passwordPhoto)    # am codat textul cu parola dată

    imgAux = image.copy() 
    width, height = imgAux.size

    # Verific ca dimensiunea mesajului secret să nu fie mai mare decât capacitatea pozei
    nr_bytes = width * height * 3 // 8
    if (nr_bytes < len(text)):
      raise ValueError(f"Insuficienti bytes: alegeti o poza cu dimensiuni mai mari sau reduceti marimea mesajului!\nNr maxim de bytes: {nr_bytes}")
    else:
      encodeAux(imgAux, encodedMessage, output_filepath, passwordPixels, progressBar)





# Funcția Principală pentru decodare
def decode(input_path, input_path_Pixels, passwordPhoto, passwordPixels, progressBar = None): 
    key = hashlib.sha256(passwordPixels.encode()).digest()
    decrypt_file(key, input_path_Pixels, 'out.txt')
    Pixeli = np.genfromtxt('out.txt', delimiter='\t')

    if os.path.exists("out.txt"):
        os.remove("out.txt")
        
    os.remove(input_path_Pixels)

    decodedTextInBits = []
    img = Image.open(input_path, 'r') 
    width, height = img.size
    progress = 0
    for i in range(0, len(Pixeli), 3):
        ithChar = ""
        for j in range(0, 3):
            rr = Pixeli[i + j] // height
            rc = Pixeli[i + j] % height
            rgb = img.getpixel((rr, rc))
            for k in rgb:
                if (k & 1):
                    ithChar += '1'
                else:
                    ithChar += '0'

        ithChar = ithChar[:-1]
        decodedTextInBits.append((ithChar))
        
        if progressBar != None: 
            progress += 1
            progressBar.setValue(progress * 100)
        
        
    decodedText = ''
    for i in decodedTextInBits:
        decodedText += chr(int(i, 2))
    
    mesajSecret = decrypt(decodedText, passwordPhoto)
    return mesajSecret



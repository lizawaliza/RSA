from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import random, sys

def rsa_key_gen(bits=2048, content_file_path="output.txt", privatekey_path='privatek.pem', pubkey_path='publick.pem'):
    sys.set_int_max_str_digits(1000000)
    with open(content_file_path, 'rb') as content_file:
            content = content_file.read()

    def rand(n):
        index = random.randint(256, 1024)
        return content[index:index+n]
   
    private_key = RSA.generate(bits, randfunc=rand)
    with open(privatekey_path, "wb") as privkey_file:
        privkey_file.write(private_key.export_key())
    with open(pubkey_path, "wb") as pubkey_file:
        pubkey_file.write(private_key.publickey().export_key())

def sign_file(file_path, private_key_path):
    with open(file_path, 'rb') as file:
        file_content = file.read()

    with open(private_key_path, 'rb') as key_file:
        private_key = RSA.import_key(key_file.read())

    signature = pkcs1_15.new(private_key).sign(SHA256.new(file_content))

    with open("podpis.txt", 'w') as signature_file:
        signature_file.write(signature.hex())

def verify_signature(file_path, signature_path, public_key_path):
    with open(file_path, "rb") as file:
        data = file.read()
    with open(signature_path, 'r') as signature_file:
        signature = signature_file.read()
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = RSA.import_key(key_file.read())
            hash_data = SHA256.new(data)
            verifier = pkcs1_15.new(public_key)
            verifier.verify(hash_data, bytes.fromhex(signature))
            return True
    except:
        return False
    

while True:
    print("Wybierz : \n '1' podpis RSA \n '2' weryfikacja")
    option = input()
    signature = None

    try:
      with open('podpis.txt', 'r') as signature_file:
        signature = signature_file.read()
    except:
        signature = None

  
    if option == '1':
        print("Wprowadź ścieżkę do pliku: ")
        file_path = input()
        rsa_key_gen()
        sign_file(file_path, 'privatek.pem')
        print("Podpisano plik jako podpis.txt! ")

    elif option == '2':
            print("Wprowadź ścieżkę pliku do sprawdzenia podpisu: ")
            file_path = input()
            print('Wprowadź ścieżkę klucza publicznego: ')
            public_key_path = input()

            print('Wprowadź ścieżkę podpisu: ')
            signature_path = input()

            signature_to_check = bytes.fromhex(signature)

            is_verified = verify_signature(file_path, signature_path, public_key_path)
            if is_verified:
                print("Podpis jest prawidłowy, nic nie było zmieniane")
            else:
                print("Podpis się nie zgadza, plik/klucz był zmieniony bądź jest nieprawidłowy.")

    else:
        break
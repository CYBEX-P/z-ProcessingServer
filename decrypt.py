#-----------------------Decryption-------------------------


import sys, getopt

def main(argv):

    from Crypto.PublicKey import RSA
    from Crypto.Cipher import AES, PKCS1_OAEP

    f = open(argv, "rb")
    fpriv_name = "priv.pem"

    private_key = RSA.import_key(open(fpriv_name).read())

    enc_session_key, nonce, tag, ciphertext = \
       [ f.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    d = data.decode("utf-8")
    s = str(d)
    print(s)
    

if __name__ == "__main__":
   main(sys.argv[1])




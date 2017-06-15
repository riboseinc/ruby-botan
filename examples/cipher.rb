# frozen_string_literal: true

require 'botan'

# encrypt
enc = Botan::Cipher.encryption('AES-128/CBC/PKCS7')
key = Botan::RNG.get(enc.key_length_max)
iv = Botan::RNG.get(enc.default_nonce_length)
enc.key = key
enc.iv = iv
ciphertext = enc.finish('my secret message')

# decrypt
dec = Botan::Cipher.decryption('AES-128/CBC/PKCS7')
dec.key = key
dec.iv = iv
plaintext = dec.finish(ciphertext)

puts plaintext


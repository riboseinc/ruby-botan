# frozen_string_literal: true

require 'botan/kdf'
require 'botan/rng'

key = Botan::KDF.kdf(algo: 'KDF2(SHA-160)',
                     secret: Botan::RNG.get(9),
                     salt: Botan::RNG.get(7),
                     key_length: 32)
puts "Derived key: #{Botan.hex_encode(key)}"

key = Botan::KDF.pbkdf(algo: 'PBKDF2(CMAC(Blowfish))',
                       password: 'some long passphrase',
                       iterations: 150_000,
                       key_length: 16)
puts "Derived key: #{Botan.hex_encode(key)}"

result = Botan::KDF.pbkdf_timed(algo: 'PBKDF2(SHA-256)',
                                password: 'my secret passphrase',
                                key_length: 8,
                                milliseconds: 100)
puts "Ran #{result[:iterations]} iterations."
puts "Derived key: #{Botan.hex_encode(result[:key])}"


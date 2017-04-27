module Botan
  DEFAULT_KDF_ALGO = 'KDF2(SHA-256)'
  DEFAULT_KDF_SALT_LENGTH = 16
  DEFAULT_KDF_ITERATIONS = 100000
  DEFAULT_PBKDF_ALGO = 'PBKDF2(SHA-256)'

  DEFAULT_EME = 'EME1(SHA-256)'
  DEFAULT_EMSA = {'RSA' => 'EMSA4(SHA-256)',
                  'DSA' => 'EMSA1(SHA-256)',
                  'ECDSA' => 'EMSA1(SHA-256)',
                  'ECKCDSA' => 'EMSA1(SHA-256)',
                  'ECGDSA' => 'EMSA1(SHA-256)',
                  'GOST-34.10' => 'EMSA1(SHA-256)'}

  DEFAULT_AEAD = 'AES-256/OCB'
end # module


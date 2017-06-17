# ruby-botan [![codecov.io](https://codecov.io/github/riboseinc/ruby-botan/coverage.svg?branch=master)](https://codecov.io/github/riboseinc/ruby-botan?branch=master)

ruby-botan is a Ruby interface to [Botan](https://botan.randombit.net/).

**Note**: Refer to the Botan documentation in addition to the documentation here. In particular, this note from the Botan manual applies here as well:

> You should have some knowledge of cryptography **before** trying to use the library. This is an area where it is very easy to make mistakes, and where things are often subtle and/or counterintuitive. Obviously the library tries to provide things at a high level precisely to minimize the number of ways things can go wrong, but naive use will almost certainly not result in a secure system.

# Requirements

## Ruby

ruby-botan is currently tested to work with:

* Ruby 2.3
* Ruby 2.4

## Botan

[Botan](https://botan.randombit.net/) version 2.2 or newer is required.

# Basic Usage

The samples below are meant to be a brief introduction to the library. Refer to the full documentation for full details.

Also see the [examples](examples/) directory for examples on using various parts of the library.

## Utilities

```ruby
Botan.hex_encode("\x01\x02\x03\x04")

Botan.hex_decode('01020304')
```

## RNG - Random Number Generation

```ruby
# shortcut method that uses default RNG to get 10 bytes
Botan::RNG.get(10)

# create a different type of RNG, and reseed from the system RNG
rng = Botan::RNG.new('user')
rng.reseed
rng.get(5)
```

## Digest / Hash

There are a few different ways to utilize Digest. Which method you choose may depend on whether the data is immediately available in full, or whether it is becoming available over time.

### Simple One-Shot Hash

If you simply want to hash some data that you have immediately available in full, you may want to do something like the following.

```ruby
Botan::Digest::MD5.digest('my data')

Botan::Digest::SHA256.hexdigest('my data')
```

You may also use a longer form, in case there is not a pre-defined class (like `MD5` and `SHA256` above). For example:

```ruby
Botan::Digest.digest('Comb4P(SHA-160,RIPEMD-160)', 'my data')

Botan::Digest.hexdigest('SHA-3(224)', 'my data')
```

### Continuously Updated Hash

If you have a stream of incoming data that is not readily available that you want to hash, you may proceed in a couple of ways:

```ruby
# MD5
md5 = Botan::Digest::MD5.new
md5.update('my ')
md5 << 'data'
md5.hexdigest

# Comb4P hash combiner
hash = Botan::Digest.new('Comb4P(SHA-160,RIPEMD-160)')
hash << 'my '
hash << 'data'
hash.hexdigest
```

## Cipher

```ruby
# encrypt
enc = Botan::Cipher.encryption('AES-128/CBC/PKCS7')
key = Botan::RNG.get(enc.key_length_max)
iv = Botan::RNG.get(enc.default_nonce_length)
enc.key = key
enc.iv = iv
ciphertext = enc.finish('my data')

# decrypt
dec = Botan::Cipher.decryption('AES-128/CBC/PKCS7')
dec.key = key
dec.iv = iv
plaintext = dec.finish(ciphertext)
```

## BCrypt

The `Botan::BCrypt` module supports simple bcrypt password hashing.

```ruby
# generate password hash
password_input = gets.chomp
password_hash = Botan::BCrypt.hash(password_input, work_factor: 10)

# check password
password_input = gets.chomp
Botan::BCrypt.valid?(password: password_input, phash: password_hash)
```

## KDF - Key Derivation Functions

The `Botan::KDF` module has a few different functions for key derivation.

```ruby
Botan::KDF.kdf(algo: 'KDF2(SHA-160)', secret: Botan::RNG.get(9), salt: Botan::RNG.get(7), key_length: 32)

Botan::KDF.pbkdf(algo: 'PBKDF2(CMAC(Blowfish))', password: 'some long passphrase', iterations: 150_000, key_length: 16)

Botan::KDF.pbkdf_timed(algo: 'PBKDF2(SHA-256)', password: 'my secret passphrase', key_length: 8, milliseconds: 100)
```

## MAC - Message Authentication Code

```ruby
hmac = Botan::MAC.new('HMAC(SHA-256)')
hmac.key = Botan.hex_decode('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20')
hmac << "\x61\x62\x63"
hmac.hexdigest
```

## PK - Public Key Cryptography

The `Botan::PK` module exposes functionality for public key loading, exporting, encryption, decryption, signing, and verification.

### Key Generation

```ruby
# generate a 4096-bit RSA key
privkey = Botan::PK::PrivateKey.generate('RSA', params: '4096')

# generate an ECDSA key with group secp384r1
privkey = Botan::PK::PrivateKey.generate('ECDSA', params: 'secp384r1')

# generate a 4096-bit ElGamal key
privkey = Botan::PK::PrivateKey.generate('ElGamal', params: 'modp/ietf/4096')
```

### Key Loading

```ruby
# load a public key
pubkey = Botan::PK::PublicKey.from_data(File.read('some_file.pem'))

# load an encrypted private key
privkey = Botan::PK::PrivateKey.from_data(File.read('some_file.pem'), password: 'my key password')

# load an unencrypted private key
privkey = Botan::PK::PrivateKey.from_data(File.read('some_file.pem'))
```

### Key Exporting

```ruby
# private key export (PEM)
pem = privkey.export_pem(password: 'my secret password')

# public key export (PEM)
pem = pubkey.export_pem
```

### Encryption / Decryption

```ruby
# using defaults
ciphertext = pubkey.encrypt('my data')
plaintext = privkey.decrypt(ciphertext)
```

### Signing / Verifying

```ruby
data = 'my data'

# using defaults
signature = privkey.sign(data)
valid = pubkey.verify(data: data, signature: signature)
```

## X.509 Certificates

### Certificate Loading

```ruby
# load from a file
cert = Botan::X509::Certificate.from_file('my cert.crt')

# load from some data in memory
cert = Botan::X509::Certificate.from_data(File.read('my cert.crt'))
```

### Certificate Properties

```ruby
# fingerprint
fpr = cert.fingerprint('SHA-256')

# subject's public key
pubkey = cert.subject_public_key
```

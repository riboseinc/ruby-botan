# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'botan/cipher'
require 'botan/error'

module Botan
  # One-shot AEAD helpers with a normalized wire format.
  #
  # The returned blob is always `ciphertext || tag`, regardless of the
  # mode's native layout (SIV-family modes prefix the tag — RFC 8452
  # AES-GCM-SIV, RFC 5297 SIV — while GCM and ChaCha20-Poly1305 append
  # it). This keeps callers away from per-mode tag placement pitfalls.
  #
  # @example
  #   blob = Botan::Aead.encrypt('AES-256-GCM-SIV', key, nonce, data, ad: ad)
  #   data2 = Botan::Aead.decrypt('AES-256-GCM-SIV', key, nonce, blob, ad: ad)
  module Aead
    module_function

    # Returns true for modes whose native output prefixes the tag.
    #
    # @api private
    def tag_prefixed?(algo)
      algo.include?('SIV')
    end

    # Encrypts `plaintext` with an AEAD.
    #
    # @param algo [String] the AEAD (e.g. `AES-256-GCM-SIV`,
    #   `AES-256-GCM`, `ChaCha20-Poly1305`)
    # @param key [String] the key
    # @param nonce [String] the nonce (12 bytes for most AEADs)
    # @param plaintext [String] the data to encrypt
    # @param ad [String, nil] the associated data
    # @return [String] the blob: ciphertext followed by the tag
    def encrypt(algo, key, nonce, plaintext, ad: nil)
      enc = Cipher.encryption(algo)
      enc.key = key
      enc.auth_data = ad if ad
      enc.iv = nonce
      out = enc.finish(plaintext)
      tag_len = enc.tag_length
      if tag_prefixed?(algo)
        # native layout is tag || ciphertext; rotate to ct || tag
        out[tag_len..] + out[0, tag_len]
      else
        out
      end
    end

    # Decrypts a blob produced by {encrypt}.
    #
    # @param algo [String] the AEAD
    # @param key [String] the key
    # @param nonce [String] the nonce
    # @param blob [String] the blob: ciphertext followed by the tag
    # @param ad [String, nil] the associated data
    # @return [String] the plaintext
    # @raise [Botan::Error] if authentication fails
    def decrypt(algo, key, nonce, blob, ad: nil)
      dec = Cipher.decryption(algo)
      dec.key = key
      dec.auth_data = ad if ad
      dec.iv = nonce
      tag_len = dec.tag_length
      msg = if tag_prefixed?(algo)
        # blob is ciphertext || tag (wrapper format); the mode's native
        # layout prefixes the tag.
        ct_len = blob.bytesize - tag_len
        blob[ct_len..] + blob[0, ct_len]
      else
        blob
      end
      dec.finish(msg)
    end
  end # module
end # module

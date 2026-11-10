# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'ffi'

require 'botan/ffi/libbotan'
require 'botan/utils'

module Botan
  module PK
    # McEliece (and with it mceies) was removed in Botan 3.0; guard with
    # a clear message instead of a bare FFI failure.
    def self.mceies_unavailable!
      return if LibBotan.botan_version_major < 3

      raise Botan::Error, 'McEliece support was removed in Botan 3; use a Botan 2 library for mceies'
    end

    # Encrypts with McEliece.
    #
    # @param public_key [Botan::PK::PublicKey] the public key
    # @param plaintext [String] the data to encrypt
    # @param ad [String] the associated data
    # @param aead [String] the (AEAD) cipher+mode
    # @param rng [Botan::RNG] the RNG to use
    # @return [String] the encrypted data
    def self.mceies_encrypt(public_key:, plaintext:, ad:,
                            aead: DEFAULT_AEAD,
                            rng: Botan::RNG.new)
      mceies_unavailable!
      pt_buf = FFI::MemoryPointer.from_data(plaintext)
      ad_buf = FFI::MemoryPointer.from_data(ad)
      Botan.call_ffi_with_buffer(lambda { |b, bl|
        LibBotan.botan_mceies_encrypt(public_key.ptr,
                                      rng.ptr,
                                      aead,
                                      pt_buf,
                                      pt_buf.size,
                                      ad_buf,
                                      ad_buf.size,
                                      b,
                                      bl)
      })
    end

    # Decrypts with McEliece.
    #
    # @param private_key [Botan::PK::PrivateKey] the private key
    # @param ciphertext [String] the data to decrypt
    # @param ad [String] the associated data
    # @param aead [String] the (AEAD) cipher+mode
    # @return [String] the decrypted data
    def self.mceies_decrypt(private_key:, ciphertext:, ad:,
                            aead: DEFAULT_AEAD)
      mceies_unavailable!
      ct_buf = FFI::MemoryPointer.from_data(ciphertext)
      ad_buf = FFI::MemoryPointer.from_data(ad)
      Botan.call_ffi_with_buffer(lambda { |b, bl|
        LibBotan.botan_mceies_decrypt(private_key.ptr,
                                      aead,
                                      ct_buf,
                                      ct_buf.size,
                                      ad_buf,
                                      ad.size,
                                      b,
                                      bl)
      })
    end
  end # module
end # module


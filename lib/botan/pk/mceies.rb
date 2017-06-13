# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

require 'botan/utils'

module Botan
  module PK
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
      pt_buf = FFI::MemoryPointer.from_data(plaintext)
      ad_buf = FFI::MemoryPointer.from_data(ad)
      Botan.call_ffi_with_buffer(lambda {|b,bl|
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
      ct_buf = FFI::MemoryPointer.from_data(ciphertext)
      ad_buf = FFI::MemoryPointer.from_data(ad)
      Botan.call_ffi_with_buffer(lambda {|b,bl|
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


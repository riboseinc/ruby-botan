require 'botan/utils'

module Botan
  def self.mceies_encrypt(public_key:, plaintext:, ad:, aead: DEFAULT_AEAD, rng: Botan::RNG.new)
    pt_buf = FFI::MemoryPointer.new(:uint8, plaintext.bytesize)
    pt_buf.write_bytes(plaintext)
    ad_buf = FFI::MemoryPointer.new(:uint8, ad.bytesize)
    ad_buf.write_bytes(ad)
    call_ffi_with_buffer(lambda {|b,bl|
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

  def self.mceies_decrypt(private_key:, ciphertext:, ad:, aead: DEFAULT_AEAD)
    ct_buf = FFI::MemoryPointer.new(:uint8, ciphertext.bytesize)
    ct_buf.write_bytes(ciphertext)
    ad_buf = FFI::MemoryPointer.new(:uint8, ad.bytesize)
    ad_buf.write_bytes(ad)
    call_ffi_with_buffer(lambda {|b,bl|
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


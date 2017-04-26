require 'botan/utils'

module Botan
  def self.mceies_encrypt(mce, rng, aead, pt, ad)
    pt_buf = FFI::MemoryPointer.new(:uint8, pt.bytesize)
    pt_buf.write_bytes(pt)
    ad_buf = FFI::MemoryPointer.new(:uint8, ad.bytesize)
    ad_buf.write_bytes(ad)
    call_ffi_returning_vec(0, lambda {|b,bl|
      LibBotan.botan_mceies_encrypt(mce.ptr,
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

  def self.mceies_decrypt(mce, aead, ct, ad)
    ct_buf = FFI::MemoryPointer.new(:uint8, ct.bytesize)
    ct_buf.write_bytes(ct)
    ad_buf = FFI::MemoryPointer.new(:uint8, ad.bytesize)
    ad_buf.write_bytes(ad)
    call_ffi_returning_vec(0, lambda {|b,bl|
      LibBotan.botan_mceies_decrypt(mce.ptr,
                                    aead,
                                    ct_buf,
                                    ct.size,
                                    ad_buf,
                                    ad.size,
                                    b,
                                    bl)
    })
  end
end # module


module Botan
  def self.bcrypt(password, work_factor: 10, rng: Botan::RNG.new)
    out_len = 64
    out_buf = FFI::MemoryPointer.new(:uint8, out_len)
    flags = 0
    out_len_ptr = FFI::MemoryPointer.new(:size_t)
    out_len_ptr.write(:size_t, out_len)
    Botan.call_ffi(:botan_bcrypt_generate,
                   out_buf, out_len_ptr,
                   password, rng.ptr, work_factor, flags)
    result = out_buf.read_bytes(out_len_ptr.read(:size_t))
    result = result[0..-2] if result[-1] == "\x00"
    result
  end

  def self.bcrypt_valid?(password:, phash:)
    rc = Botan.call_ffi_rc(:botan_bcrypt_is_valid, password, phash)
    return rc == 0
  end
end # module


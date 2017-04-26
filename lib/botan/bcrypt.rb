module Botan
  def self.bcrypt(passwd, rng, work_factor=10)
    out_len = 64
    out_buf = FFI::MemoryPointer.new(:uint8, out_len)
    flags = 0
    out_len_ptr = FFI::MemoryPointer.new(:size_t)
    out_len_ptr.write(:size_t, out_len)
    Botan.call_ffi(:botan_bcrypt_generate,
                   out_buf, out_len_ptr,
                   passwd, rng.ptr, work_factor, flags)
    result = out_buf.read_bytes(out_len_ptr.read(:size_t))
    result = result[0..-2] if result[-1] == "\x00"
    result
  end

  def self.check_bcrypt(passwd, bcrypt)
    rc = LibBotan.botan_bcrypt_is_valid(passwd, bcrypt)
    return rc == 0
  end
end # module


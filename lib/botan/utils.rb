module Botan
  def self.call_fn_returning_vec(guess, fn)
    buf = FFI::MemoryPointer.new(:uint8, guess)
    buf_len_ptr = FFI::MemoryPointer.new(:size_t)
    buf_len_ptr.write(:size_t, buf.size)

    rc = fn.call(buf, buf_len_ptr)
    buf_len = buf_len_ptr.read(:size_t)
    if rc < 0
      raise unless buf_len > buf.size
      return call_fn_returning_vec(buf_len, fn)
    else
      raise unless buf_len <= buf.size
      buf.read_bytes(buf_len)
    end
  end

  def self.call_fn_returning_string(guess, fn)
    bytes = call_fn_returning_vec(guess, fn)
    bytes[0..-2].force_encoding('ascii-8bit')
  end
end # module


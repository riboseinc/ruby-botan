module Botan
  def self.call_ffi(fn, *args)
    rc = LibBotan.method(fn).call(*args)
    if rc < 0
      raise Botan::Error, "FFI call to #{fn.to_s} failed"
    end
    rc
  end

  def self.call_ffi_returning_vec(guess, fn)
    buf = FFI::MemoryPointer.new(:uint8, guess)
    buf_len_ptr = FFI::MemoryPointer.new(:size_t)
    buf_len_ptr.write(:size_t, buf.size)

    rc = fn.call(buf, buf_len_ptr)
    buf_len = buf_len_ptr.read(:size_t)
    if rc < 0
      raise unless buf_len > buf.size
      return call_ffi_returning_vec(buf_len, fn)
    else
      raise unless buf_len <= buf.size
      buf.read_bytes(buf_len)
    end
  end

  def self.call_ffi_returning_string(guess, fn)
    bytes = call_ffi_returning_vec(guess, fn)
    bytes[0..-2].force_encoding('ascii-8bit')
  end

  def self.hex_encode(bytes)
    bytes.unpack('H*')[0]
  end

  def self.hex_decode(hexs)
    [hexs].pack('H*')
  end
end # module


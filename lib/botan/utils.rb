module Botan
  def self.call_ffi_rc(fn, *args)
    rc = LibBotan.method(fn).call(*args)
    if rc < 0
      raise Botan::Error, "FFI call to #{fn.to_s} failed (rc: #{rc})"
    end
    rc
  end

  def self.call_ffi(fn, *args)
    call_ffi_rc(fn, *args)
    nil
  end

  def self.call_ffi_with_buffer(fn, guess: 4096, string: false)
    buf = FFI::MemoryPointer.new(:uint8, guess)
    buf_len_ptr = FFI::MemoryPointer.new(:size_t)
    buf_len_ptr.write(:size_t, buf.size)

    rc = fn.call(buf, buf_len_ptr)
    buf_len = buf_len_ptr.read(:size_t)
    # Call should only fail if buffer was inadequate, and should
    # only succeed if buffer was adequate.
    if (rc < 0 && buf_len <= buf.size) || (rc >=0 && buf_len > buf.size)
      raise Botan::Error, 'FFI call unexpectedly failed'
    end

    if rc < 0
      return call_ffi_with_buffer(fn, guess: buf_len, string: string)
    else
      string ? buf.read_string : buf.read_bytes(buf_len)
    end
  end

  # TODO: Upstream this.
  class << FFI::MemoryPointer
    def from_data(data)
      buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
      buf.write_bytes(data)
      buf
    end
  end if not FFI::MemoryPointer.respond_to?(:from_data)

  def self.hex_encode(data)
    data.unpack('H*')[0]
  end

  def self.hex_decode(hexs)
    [hexs].pack('H*')
  end
end # module


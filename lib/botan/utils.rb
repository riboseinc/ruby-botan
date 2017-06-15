# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

require 'ffi'

require 'botan/error'
require 'botan/ffi/libbotan'

module Botan
  # @api private
  #
  # Calls the LibBotan FFI function indicated and returns the return code.
  # If the return code is <0, an error will be raised.
  #
  # @param fn [Symbol] the name of the function to call
  # @param args the arguments to pass to the FFI function
  # @return [Integer] the return code
  def self.call_ffi_rc(fn, *args)
    rc = LibBotan.method(fn).call(*args)
    if rc < 0
      raise Botan::Error, "FFI call to #{fn.to_s} failed (rc: #{rc})"
    end
    rc
  end

  # @api private
  #
  # Calls the LibBotan FFI function indicated.
  # If the return code is <0, an error will be raised.
  #
  # @param fn [Symbol] the name of the function to call
  # @param args the arguments to pass to the FFI function
  # @return [void]
  def self.call_ffi(fn, *args)
    call_ffi_rc(fn, *args)
    nil
  end

  # @api private
  #
  # Calls the LibBotan FFI function indicated
  # If the return code is <0, an error will be raised.
  #
  # @param fn [#call] a proc/lambda taking two parameters.
  # @param guess [Integer] an initial guess for the buffer size
  # @param string [Boolean] true if the returned buffer is expected
  #   to be a NULL-terminated string.
  # @return [String] the data
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

  def self.inspect_ptr(myself)
    ptr_format = "0x%0#{FFI::Pointer.size*2}x"
    ptr_s = sprintf(ptr_format, myself.instance_variable_get(:@ptr).address)
    class_name = myself.class.to_s
    "#<#{class_name}:#{ptr_s}>"
  end

  # @api private
  # TODO: Upstream this.
  class << FFI::MemoryPointer
    def from_data(data)
      buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
      buf.write_bytes(data)
      buf
    end
  end if not FFI::MemoryPointer.respond_to?(:from_data)

  # Encodes the provided data as a hexadecimal string.
  #
  # @param data [String] the data to encode
  # @return [String] the data as a hexadecimal string
  def self.hex_encode(data)
    data.unpack('H*')[0]
  end

  # Decodes the provided hexadecimal string to a byte string.
  #
  # @param hexs [String] the hexadecimal string
  # @return [String] the decoded data
  def self.hex_decode(hexs)
    [hexs].pack('H*')
  end
end # module


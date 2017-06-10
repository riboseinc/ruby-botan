module Botan
  class MAC
    def initialize(algo)
      flags = 0
      mac_ptr = FFI::MemoryPointer.new(:pointer)
      Botan.call_ffi(:botan_mac_init, mac_ptr, algo, flags)
      @ptr = mac_ptr.read_pointer
      if @ptr.null?
        raise Botan::Error, 'botan_mac_init returned NULL'
      end
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan.botan_mac_destroy(ptr)
    end

    def reset
      Botan.call_ffi(:botan_mac_clear, @ptr)
      self
    end

    def output_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_mac_output_length, @ptr, length_ptr)
      length_ptr.read(:size_t)
    end

    def key=(key)
      Botan.call_ffi(:botan_mac_set_key, @ptr, key, key.bytesize)
    end

    def update(data)
      Botan.call_ffi(:botan_mac_update, @ptr, data, data.bytesize)
      self
    end

    def digest
      out_buf = FFI::MemoryPointer.new(:uint8, output_length())
      Botan.call_ffi(:botan_mac_final, @ptr, out_buf)
      out_buf.read_bytes(out_buf.size)
    end

    def hexdigest
      Botan.hex_encode(digest)
    end

    alias << update

    # TODO: it's not safe to do this at the moment, since these
    # methods mutate the state.
    #alias inspect hexdigest
    #alias to_s hexdigest
  end # class
end # module


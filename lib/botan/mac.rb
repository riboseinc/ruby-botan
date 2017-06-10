module Botan
  # Message Authentication Code
  #
  # == Examples
  # === examples/mac.rb
  # {include:file:examples/mac.rb}
  class MAC
    # @param algo [String] the MAC algorithm name
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

    # @api private
    def self.destroy(ptr)
      LibBotan.botan_mac_destroy(ptr)
    end

    # Resets the instace back to a clean state, as if no key and
    # input have been supplied.
    #
    # @return [self]
    def reset
      Botan.call_ffi(:botan_mac_clear, @ptr)
      self
    end

    # Retrieve the output length of the MAC.
    #
    # @return [Integer]
    def output_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_mac_output_length, @ptr, length_ptr)
      length_ptr.read(:size_t)
    end

    # Sets the key for the MAC.
    # This must be called before {#update}.
    #
    # @param [String] key
    def key=(key)
      Botan.call_ffi(:botan_mac_set_key, @ptr, key, key.bytesize)
    end

    # Adds input to the MAC computation.
    #
    # @param [String] data
    # @return [self]
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


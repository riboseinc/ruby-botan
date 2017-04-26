module Botan
  class RNG
    attr_reader :ptr
    def initialize(rng_type='system')
      rng_ptr = FFI::MemoryPointer.new(:pointer)
      Botan.call_ffi(:botan_rng_init, rng_ptr, rng_type)
      @ptr = rng_ptr.read_pointer
      if @ptr.null?
        raise Botan::Error, 'botan_rng_init returned NULL'
      end
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan.botan_rng_destroy(ptr)
    end

    def reseed(bits=256)
      Botan.call_ffi(:botan_rng_reseed, @ptr, bits)
    end

    def get(length)
      out_buf = FFI::MemoryPointer.new(:uint8, length)
      Botan.call_ffi(:botan_rng_get, @ptr, out_buf, length)
      out_buf.read_bytes(length)
    end
  end # class
end # module


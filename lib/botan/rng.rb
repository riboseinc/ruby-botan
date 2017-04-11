module Botan
  class RNG
    attr_reader :ptr
    def initialize(rng_type='system')
      rng_ptr = FFI::MemoryPointer.new(:pointer)
      rc = LibBotan.botan_rng_init(rng_ptr, rng_type)
      raise if rc != 0
      @ptr = rng_ptr.read_pointer
      raise if @ptr.null?
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan.botan_rng_destroy(ptr)
    end

    def reseed(bits=256)
      rc = LibBotan.botan_rng_reseed(@ptr, bits)
      raise if rc != 0
    end

    def get(length)
      out_buf = FFI::MemoryPointer.new(:uint8, length)
      rc = LibBotan.botan_rng_get(@ptr, out_buf, length)
      raise if rc != 0
      out_buf.read_bytes(length)
    end
  end # class
end # module


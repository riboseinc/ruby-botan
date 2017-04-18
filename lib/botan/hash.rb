module Botan
  class Hash
    def initialize(algo)
      flags = 0
      hash_ptr = FFI::MemoryPointer.new(:pointer)
      rc = LibBotan.botan_hash_init(hash_ptr, algo, flags)
      raise if rc != 0
      @ptr = hash_ptr.read_pointer
      raise if @ptr.null?
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan.botan_hash_destroy(ptr)
    end

    def clear
      rc = LibBotan.botan_hash_clear(@ptr)
      raise if rc != 0
    end

    def output_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      rc = LibBotan.botan_hash_output_length(@ptr, length_ptr)
      raise if rc != 0
      length_ptr.read(:size_t)
    end

    def update(x)
      rc = LibBotan.botan_hash_update(@ptr, x, x.bytesize)
      raise if rc != 0
    end

    def <<(x)
      update(x)
    end

    def final
      out_buf = FFI::MemoryPointer.new(:uint8, output_length())
      rc = LibBotan.botan_hash_final(@ptr, out_buf)
      raise if rc != 0
      out_buf.read_bytes(out_buf.size)
    end
  end # class
end # module


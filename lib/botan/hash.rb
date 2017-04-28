module Botan
  class Hash
    def initialize(algo)
      flags = 0
      hash_ptr = FFI::MemoryPointer.new(:pointer)
      Botan.call_ffi(:botan_hash_init, hash_ptr, algo, flags)
      @ptr = hash_ptr.read_pointer
      if @ptr.null?
        raise Botan::Error, 'botan_hash_init returned NULL'
      end
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan.botan_hash_destroy(ptr)
    end

    def clear
      Botan.call_ffi(:botan_hash_clear, @ptr)
    end

    def output_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_hash_output_length, @ptr, length_ptr)
      length_ptr.read(:size_t)
    end

    def update(data)
      Botan.call_ffi(:botan_hash_update, @ptr, data, data.bytesize)
    end

    def <<(data)
      update(data)
    end

    def final
      out_buf = FFI::MemoryPointer.new(:uint8, output_length())
      Botan.call_ffi(:botan_hash_final, @ptr, out_buf)
      out_buf.read_bytes(out_buf.size)
    end
  end # class
end # module


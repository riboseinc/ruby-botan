module Botan
  class MAC
    def initialize(algo)
      flags = 0
      mac_ptr = FFI::MemoryPointer.new(:pointer)
      rc = LibBotan.botan_mac_init(mac_ptr, algo, flags)
      raise if rc != 0
      @ptr = mac_ptr.read_pointer
      raise if @ptr.null?
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan.botan_mac_destroy(ptr)
    end

    def clear
      rc = LibBotan.botan_mac_clear(@ptr)
      raise if rc != 0
    end

    def output_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      rc = LibBotan.botan_mac_output_length(@ptr, length_ptr)
      raise if rc != 0
      length_ptr.read(:size_t)
    end

    def set_key(key)
      rc = LibBotan.botan_mac_set_key(@ptr, key, key.bytesize)
      raise if rc != 0
    end

    def update(x)
      rc = LibBotan.botan_mac_update(@ptr, x, x.bytesize)
      raise if rc != 0
    end

    def <<(x)
      update(x)
    end

    def final
      out_buf = FFI::MemoryPointer.new(:uint8, output_length())
      rc = LibBotan.botan_mac_final(@ptr, out_buf)
      raise if rc != 0
      out_buf.read_bytes(out_buf.size)
    end
  end # class
end # module


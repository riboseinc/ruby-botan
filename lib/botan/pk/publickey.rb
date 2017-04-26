module Botan
  module PK
    class PublicKey
      attr_reader :ptr
      def initialize(ptr)
        @ptr = ptr
        raise if @ptr.null?
        @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
      end

      def self.destroy(ptr)
        LibBotan.botan_pubkey_destroy(ptr)
      end

      def self.load(bytes)
        ptr = FFI::MemoryPointer.new(:pointer)
        buf = FFI::MemoryPointer.new(:uint8, bytes.bytesize)
        buf.write_bytes(bytes)
        Botan.call_ffi(:botan_pubkey_load, ptr, buf, buf.size)
        PublicKey.new(ptr.read_pointer)
      end

      def estimated_strength
        strength_ptr = FFI::MemoryPointer.new(:size_t)
        Botan.call_ffi(:botan_pubkey_estimated_strength, @ptr, strength_ptr)
        strength_ptr.read(:size_t)
      end

      def algo_name
        Botan.call_ffi_returning_string(32, lambda {|b, bl|
          LibBotan.botan_pubkey_algo_name(@ptr, b, bl)
        })
      end

      def export(pem=false)
        flags = pem ? 1 : 0
        if pem
          Botan.call_ffi_returning_string(0, lambda {|b, bl|
            LibBotan.botan_pubkey_export(@ptr, b, bl, flags)
          })
        else
          Botan.call_ffi_returning_vec(0, lambda {|b, bl|
            LibBotan.botan_pubkey_export(@ptr, b, bl, flags)
          })
        end
      end

      def fingerprint(hash='SHA-256')
        n = Hash.new(hash).output_length
        buf = FFI::MemoryPointer.new(:uint8, n)
        buf_len_ptr = FFI::MemoryPointer.new(:size_t)
        buf_len_ptr.write(:size_t, n)
        Botan.call_ffi(:botan_pubkey_fingerprint, @ptr, hash, buf, buf_len_ptr)
        bytes = buf.read_bytes(buf_len_ptr.read(:size_t))
        bytes.unpack('H*')[0]
      end
    end # class
  end # module
end # module


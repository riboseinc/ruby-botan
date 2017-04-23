module Botan
  module PK
    class PublicKey
      attr_reader :ptr
      def initialize(obj=nil)
        @ptr = obj
        @ptr_auto = nil
        if @ptr
          @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
        end
      end

      def self.destroy(ptr)
        LibBotan.botan_pubkey_destroy(ptr)
      end

      def estimated_strength
        strength_ptr = FFI::MemoryPointer.new(:size_t)
        rc = LibBotan.botan_pubkey_estimated_strength(@ptr, strength_ptr)
        raise if rc != 0
        strength_ptr.read(:size_t)
      end

      def algo_name
        Botan.call_fn_returning_string(32, lambda {|b, bl| LibBotan.botan_pubkey_algo_name(@ptr, b, bl)})
      end

      def export(pem=false)
        flag = pem ? 1 : 0
        if pem
          Botan.call_fn_returning_string(0, lambda {|b, bl| LibBotan.botan_pubkey_export(@ptr, b, bl, flag)})
        else
          Botan.call_fn_returning_vec(0, lambda {|b, bl| LibBotan.botan_pubkey_export(@ptr, b, bl, flag)})
        end
      end

      def fingerprint(hash='SHA-256')
        n = Hash.new(hash).output_length
        buf = FFI::MemoryPointer.new(:uint8, n)
        buf_len_ptr = FFI::MemoryPointer.new(:size_t)
        buf_len_ptr.write(:size_t, n)
        rc = LibBotan.botan_pubkey_fingerprint(@ptr, hash, buf, buf_len_ptr)
        raise if rc != 0
        bytes = buf.read_bytes(buf_len_ptr.read(:size_t))
        bytes.unpack('H*')[0]
      end
    end # class
  end # module
end # module


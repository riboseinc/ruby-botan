module Botan
  module PK
    class KeyAgreement
      attr_reader :public_value
      def initialize(key, kdf)
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        rc = LibBotan.botan_pk_op_key_agreement_create(ptr, key.ptr, kdf, flags)
        raise if rc != 0
        @ptr = ptr.read_pointer
        raise if @ptr.null?
        @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
        @public_value = Botan.call_fn_returning_vec(0, lambda {|b,bl| LibBotan.botan_pk_op_key_agreement_export_public(key.ptr, b, bl)})
      end

      def self.destroy(ptr)
        LibBotan.botan_pk_op_key_agreement_destroy(ptr)
      end

      def agree(other, key_len, salt)
        other_buf = FFI::MemoryPointer.new(:uint8, other.bytesize)
        other_buf.write_bytes(other)
        salt_buf = FFI::MemoryPointer.new(:uint8, salt.bytesize)
        salt_buf.write_bytes(salt)
        Botan.call_fn_returning_vec(key_len, lambda {|b,bl| LibBotan.botan_pk_op_key_agreement(@ptr, b, bl, other_buf, other_buf.size, salt_buf, salt_buf.size)})
      end
    end # class
  end # module
end # module


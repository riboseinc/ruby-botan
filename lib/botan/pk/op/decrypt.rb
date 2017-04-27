module Botan
  module PK
    class Decrypt
      def initialize(private_key:, padding: nil)
        padding ||= Botan::DEFAULT_EME
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        Botan.call_ffi(:botan_pk_op_decrypt_create,
                       ptr, private_key.ptr, padding, flags)
        @ptr = ptr.read_pointer
        if @ptr.null?
          raise Botan::Error, 'botan_pk_op_decrypt_create returned NULL'
        end
        @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
      end

      def self.destroy(ptr)
        LibBotan.botan_pk_op_decrypt_destroy(ptr)
      end

      def decrypt(msg)
        msg_buf = FFI::MemoryPointer.new(:uint8, msg.bytesize)
        msg_buf.write_bytes(msg)
        Botan.call_ffi_returning_vec(4096, lambda {|b, bl|
          LibBotan.botan_pk_op_decrypt(@ptr, b, bl, msg_buf, msg_buf.size)
        })
      end
    end # class
  end # module
end # module


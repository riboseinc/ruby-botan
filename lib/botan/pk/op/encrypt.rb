module Botan
  module PK
    class Encrypt
      def initialize(public_key:, padding: nil)
        padding ||= Botan::DEFAULT_EME
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        Botan.call_ffi(:botan_pk_op_encrypt_create,
                       ptr, public_key.ptr, padding, flags)
        @ptr = ptr.read_pointer
        if @ptr.null?
          raise Botan::Error, 'botan_pk_op_encrypt_create returned NULL'
        end
        @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
      end

      def self.destroy(ptr)
        LibBotan.botan_pk_op_encrypt_destroy(ptr)
      end

      def encrypt(msg, rng: Botan::RNG.new)
        msg_buf = FFI::MemoryPointer.from_data(msg)
        Botan.call_ffi_with_buffer(lambda {|b, bl|
          LibBotan.botan_pk_op_encrypt(@ptr, rng.ptr, b, bl, msg_buf, msg_buf.size)
        })
      end
    end # class
  end # module
end # module


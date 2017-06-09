module Botan
  module PK
    class Verify
      def initialize(public_key:, padding: nil)
        padding ||= Botan::DEFAULT_EMSA[public_key.algo_name]
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        Botan.call_ffi(:botan_pk_op_verify_create,
                       ptr, public_key.ptr, padding, flags)
        @ptr = ptr.read_pointer
        if @ptr.null?
          raise Botan::Error, 'botan_pk_op_verify_create returned NULL'
        end
        @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
      end

      def self.destroy(ptr)
        LibBotan.botan_pk_op_verify_destroy(ptr)
      end

      def update(msg)
        msg_buf = FFI::MemoryPointer.from_data(msg)
        Botan.call_ffi(:botan_pk_op_verify_update, @ptr, msg_buf, msg_buf.size)
        self
      end

      def <<(msg)
        update(msg)
      end

      def check_signature(signature)
        sig_buf = FFI::MemoryPointer.from_data(signature)
        rc = Botan.call_ffi_rc(:botan_pk_op_verify_finish,
                               @ptr, sig_buf, sig_buf.size)
        rc == 0
      end
    end # class
  end # module
end # module


module Botan
  module PK
    class Sign
      def initialize(private_key:, padding: nil)
        padding ||= Botan::DEFAULT_EMSA[private_key.public_key.algo_name]
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        Botan.call_ffi(:botan_pk_op_sign_create, ptr, private_key.ptr, padding, flags)
        @ptr = ptr.read_pointer
        if @ptr.null?
          raise Botan::Error, 'botan_pk_op_sign_create returned NULL'
        end
        @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
      end

      def self.destroy(ptr)
        LibBotan.botan_pk_op_sign_destroy(ptr)
      end

      def update(msg)
        msg_buf = FFI::MemoryPointer.from_data(msg)
        Botan.call_ffi(:botan_pk_op_sign_update, @ptr, msg_buf, msg_buf.size)
        self
      end

      def finish(rng)
        Botan.call_ffi_with_buffer(lambda {|b, bl|
          LibBotan.botan_pk_op_sign_finish(@ptr, rng.ptr, b, bl)
        })
      end

      alias << update
    end # class
  end # module
end # module


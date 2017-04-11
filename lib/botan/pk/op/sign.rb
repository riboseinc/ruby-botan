module Botan
  module PK
    class Sign
      def initialize(key, padding)
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        rc = LibBotan.botan_pk_op_sign_create(ptr, key.ptr, padding, flags)
        raise if rc != 0
        @ptr = ptr.read_pointer
        raise if @ptr.null?
        @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
      end

      def self.destroy(ptr)
        LibBotan.botan_pk_op_sign_destroy(ptr)
      end

      def update(msg)
        msg_buf = FFI::MemoryPointer.new(:uint8, msg.bytesize)
        msg_buf.write_bytes(msg)
        rc = LibBotan.botan_pk_op_sign_update(@ptr, msg_buf, msg_buf.size)
        raise if rc != 0
      end

      def finish(rng)
        Botan.call_fn_returning_vec(4096, lambda {|b, bl| LibBotan.botan_pk_op_sign_finish(@ptr, rng.ptr, b, bl)})
      end
    end # class
  end # module
end # module


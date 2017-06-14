# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

module Botan
  module PK
    # Public Key Sign Operation
    #
    # See {Botan::PK::PrivateKey#sign} for a simpler interface.
    class Sign
      # @param private_key [Botan::PK::PrivateKey] the private key
      # @param padding [String] the padding method name
      def initialize(private_key:, padding: nil)
        padding ||= Botan::DEFAULT_EMSA[private_key.public_key.algo]
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        Botan.call_ffi(:botan_pk_op_sign_create, ptr, private_key.ptr, padding, flags)
        ptr = ptr.read_pointer
        if ptr.null?
          raise Botan::Error, 'botan_pk_op_sign_create returned NULL'
        end
        @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      end

      # @api private
      def self.destroy(ptr)
        LibBotan.botan_pk_op_sign_destroy(ptr)
      end

      # Adds data to the message currently being signed.
      #
      # @param msg [String] the data to add
      # @return [self]
      def update(msg)
        msg_buf = FFI::MemoryPointer.from_data(msg)
        Botan.call_ffi(:botan_pk_op_sign_update, @ptr, msg_buf, msg_buf.size)
        self
      end

      # Finalizes the signature operation.
      #
      # @param rng [Botan::PK::RNG] the RNG to use
      # @return [String] the signature
      def finish(rng = Botan::RNG.new)
        Botan.call_ffi_with_buffer(lambda {|b, bl|
          LibBotan.botan_pk_op_sign_finish(@ptr, rng.ptr, b, bl)
        })
      end

      def inspect
        Botan.inspect_ptr(self)
      end

      alias << update
    end # class
  end # module
end # module


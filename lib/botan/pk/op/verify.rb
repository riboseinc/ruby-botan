# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

module Botan
  module PK
    # Public Key Verify Operation
    #
    # See {Botan::PK::PublicKey#verify} for a simpler interface.
    class Verify
      # @param key [Botan::PK::PublicKey] the public key
      # @param padding [String] the padding method name
      def initialize(key:, padding: nil)
        padding ||= Botan::DEFAULT_EMSA[key.algo]
        if not key.instance_of?(PublicKey)
          raise Botan::Error, 'Verify requires an instance of PublicKey'
        end
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        Botan.call_ffi(:botan_pk_op_verify_create,
                       ptr, key.ptr, padding, flags)
        ptr = ptr.read_pointer
        if ptr.null?
          raise Botan::Error, 'botan_pk_op_verify_create returned NULL'
        end
        @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      end

      # @api private
      def self.destroy(ptr)
        LibBotan.botan_pk_op_verify_destroy(ptr)
      end

      # Adds more data to the message currently being verified.
      #
      # @param msg [String] the data to add
      # @return [self]
      def update(msg)
        msg_buf = FFI::MemoryPointer.from_data(msg)
        Botan.call_ffi(:botan_pk_op_verify_update, @ptr, msg_buf, msg_buf.size)
        self
      end

      # Checks the signature against the previously-provided data.
      #
      # @param signature [String] the signature to check
      # @return [Boolean] true if the signature is valid
      def check_signature(signature)
        sig_buf = FFI::MemoryPointer.from_data(signature)
        rc = Botan.call_ffi_rc(:botan_pk_op_verify_finish,
                               @ptr, sig_buf, sig_buf.size)
        rc == 0
      end

      def inspect
        Botan.inspect_ptr(self)
      end

      alias << update
    end # class
  end # module
end # module


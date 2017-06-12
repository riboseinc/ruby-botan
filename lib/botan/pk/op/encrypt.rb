module Botan
  module PK
    # Public Key Encrypt Operation
    #
    # See {Botan::PK::PublicKey#encrypt} for a simpler interface.
    class Encrypt
      # @param public_key [Botan::PK::PublicKey] the public key
      # @param padding [String] the padding method name
      def initialize(public_key:, padding: nil)
        padding ||= Botan::DEFAULT_EME
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        Botan.call_ffi(:botan_pk_op_encrypt_create,
                       ptr, public_key.ptr, padding, flags)
        ptr = ptr.read_pointer
        if ptr.null?
          raise Botan::Error, 'botan_pk_op_encrypt_create returned NULL'
        end
        @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      end

      # @api private
      def self.destroy(ptr)
        LibBotan.botan_pk_op_encrypt_destroy(ptr)
      end

      # Encrypts the provided data.
      #
      # @param msg [String] the data
      # @param rng [Botan::PK::RNG] the RNG to use
      # @return [String] the encrypted data
      def encrypt(msg, rng: Botan::RNG.new)
        msg_buf = FFI::MemoryPointer.from_data(msg)
        Botan.call_ffi_with_buffer(lambda {|b, bl|
          LibBotan.botan_pk_op_encrypt(@ptr, rng.ptr, b, bl, msg_buf, msg_buf.size)
        })
      end

      def inspect
        Botan.inspect_ptr(self)
      end
    end # class
  end # module
end # module


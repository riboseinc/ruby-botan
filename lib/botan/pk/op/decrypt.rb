module Botan
  module PK
    # Public Key Decrypt Operation
    #
    # See {Botan::PK::PrivateKey#decrypt} for a simpler interface.
    class Decrypt
      # @param private_key [Botan::PK::PrivateKey] the private key
      # @param padding [String] the padding method name
      def initialize(private_key:, padding: nil)
        padding ||= Botan::DEFAULT_EME
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        Botan.call_ffi(:botan_pk_op_decrypt_create,
                       ptr, private_key.ptr, padding, flags)
        ptr = ptr.read_pointer
        if ptr.null?
          raise Botan::Error, 'botan_pk_op_decrypt_create returned NULL'
        end
        @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      end

      # @api private
      def self.destroy(ptr)
        LibBotan.botan_pk_op_decrypt_destroy(ptr)
      end

      # Decrypts the provided data.
      #
      # @param msg [String] the data
      # @return [String] the decrypted data
      def decrypt(msg)
        msg_buf = FFI::MemoryPointer.from_data(msg)
        Botan.call_ffi_with_buffer(lambda {|b, bl|
          LibBotan.botan_pk_op_decrypt(@ptr, b, bl, msg_buf, msg_buf.size)
        })
      end
    end # class
  end # module
end # module


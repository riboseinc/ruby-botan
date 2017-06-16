# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'ffi'

require 'botan/defaults'
require 'botan/error'
require 'botan/ffi/libbotan'
require 'botan/pk/privatekey'
require 'botan/utils'

module Botan
  module PK
    # Public Key Decrypt Operation
    #
    # See {Botan::PK::PrivateKey#decrypt} for a simpler interface.
    class Decrypt
      # @param key [Botan::PK::PrivateKey] the private key
      # @param padding [String] the padding method name
      def initialize(key:, padding: nil)
        padding ||= Botan::DEFAULT_EME
        unless key.instance_of?(PrivateKey)
          raise Botan::Error, 'Decryption requires an instance of PrivateKey'
        end
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        Botan.call_ffi(:botan_pk_op_decrypt_create,
                       ptr, key.ptr, padding, flags)
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
        Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_pk_op_decrypt(@ptr, b, bl, msg_buf, msg_buf.size)
        })
      end

      def inspect
        Botan.inspect_ptr(self)
      end
    end # class
  end # module
end # module


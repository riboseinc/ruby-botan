# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

require 'ffi'

require 'botan/error'
require 'botan/ffi/libbotan'
require 'botan/pk/privatekey'
require 'botan/utils'

module Botan
  module PK
    # Public Key Key Agreement Operation
    class KeyAgreement
      attr_reader :public_value
      # @param key [Botan::PK::PrivateKey] the private key
      # @param kdf [String] the KDF algorithm name
      def initialize(key:, kdf: Botan::DEFAULT_KDF_ALGO)
        if not key.instance_of?(PrivateKey)
          raise Botan::Error, 'KeyAgreement requires an instance of PrivateKey'
        end
        ptr = FFI::MemoryPointer.new(:pointer)
        flags = 0
        Botan.call_ffi(:botan_pk_op_key_agreement_create,
                       ptr, key.ptr, kdf, flags)
        ptr = ptr.read_pointer
        if ptr.null?
          raise Botan::Error, 'botan_pk_op_key_agreement_create returned NULL'
        end
        @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
        @public_value = Botan.call_ffi_with_buffer(lambda {|b,bl|
          LibBotan.botan_pk_op_key_agreement_export_public(key.ptr, b, bl)
        })
      end

      # @api private
      def self.destroy(ptr)
        LibBotan.botan_pk_op_key_agreement_destroy(ptr)
      end

      def agree(other_key:, key_length:, salt:)
        other_buf = FFI::MemoryPointer.from_data(other_key)
        salt_buf = FFI::MemoryPointer.from_data(salt)
        Botan.call_ffi_with_buffer(lambda {|b,bl|
          LibBotan.botan_pk_op_key_agreement(@ptr, b, bl,
                                             other_buf, other_buf.size,
                                             salt_buf, salt_buf.size)
        }, guess: key_length)
      end

      def inspect
        Botan.inspect_ptr(self)
      end
    end # class
  end # module
end # module


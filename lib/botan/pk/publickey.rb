# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'ffi'

require 'botan/error'
require 'botan/ffi/libbotan'
require 'botan/pk/op/encrypt'
require 'botan/pk/op/verify'
require 'botan/rng'
require 'botan/utils'

module Botan
  module PK
    # Public Key
    class PublicKey
      # @api private
      attr_reader :ptr
      def initialize(ptr)
        raise Botan::Error, 'PublicKey received a NULL pointer' if ptr.null?
        @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      end

      # @api private
      def self.destroy(ptr)
        LibBotan.botan_pubkey_destroy(ptr)
      end

      # Creates a {PublicKey} from BER/PEM data.
      #
      # @param data [String] the public key data in a supported format
      # @return [Botan::PK::PublicKey]
      def self.from_data(data)
        ptr = FFI::MemoryPointer.new(:pointer)
        buf = FFI::MemoryPointer.from_data(data)
        Botan.call_ffi(:botan_pubkey_load, ptr, buf, buf.size)
        PublicKey.new(ptr.read_pointer)
      end

      # Returns the estimated strength of the key.
      #
      # @return [Integer]
      def estimated_strength
        strength_ptr = FFI::MemoryPointer.new(:size_t)
        Botan.call_ffi(:botan_pubkey_estimated_strength, @ptr, strength_ptr)
        strength_ptr.read(:size_t)
      end

      # Returns the public-key algorithm name.
      #
      # @return [String]
      def algo
        Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_pubkey_algo_name(@ptr, b, bl)
        }, guess: 32, string: true)
      end

      # Returns the PEM-encoded public key.
      #
      # @return [String]
      def export_pem
        export(pem: true)
      end

      # Returns the DER-encoded public key.
      #
      # @return [String]
      def export_der
        export(pem: false)
      end

      def to_s
        export_pem
      end

      # Returns the fingerprint of the key.
      #
      # @param hash [String] the hash algorithm to use for the calculation
      # @return [String]
      def fingerprint(hash = 'SHA-256')
        n = Botan::Digest.new(hash).length
        buf = FFI::MemoryPointer.new(:uint8, n)
        buf_len_ptr = FFI::MemoryPointer.new(:size_t)
        buf_len_ptr.write(:size_t, n)
        Botan.call_ffi(:botan_pubkey_fingerprint, @ptr, hash, buf, buf_len_ptr)
        buf.read_bytes(buf_len_ptr.read(:size_t))
      end

      # Checks whether the key appears to be valid.
      #
      # @param rng [Botan::RNG] the RNG to use
      # @param thorough [Boolean] whether to perform more thorough checks
      #   that may be slower
      # @return [Boolean] true if the key appears to be valid
      def valid?(rng = nil, thorough = false)
        rng ||= Botan::RNG.new
        flags = thorough ? 1 : 0
        rc = LibBotan.botan_pubkey_check_key(@ptr, rng.ptr, flags)
        rc.zero?
      end

      # Retrieves a field of key material.
      #
      # For example, the 'e' field of an RSA key might return
      # the value 0x1001.
      #
      # @param field [String] the name of the field to retrieve
      # @return [Integer]
      def get_field(field)
        mp = nil
        mp_ptr = FFI::MemoryPointer.new(:pointer)
        Botan.call_ffi(:botan_mp_init, mp_ptr)
        mp = mp_ptr.read_pointer
        Botan.call_ffi(:botan_pubkey_get_field, mp, @ptr, field)
        hex_str = Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_mp_to_str(mp, 16, b, bl)
        }, string: true)
        hex_str.hex
      ensure
        LibBotan.botan_mp_destroy(mp) if mp && !mp.null?
      end

      # Encrypts data using the key.
      #
      # @param data [String] the data to encrypt
      # @param padding [String] the padding method to use
      # @param rng [Botan::RNG] the RNG to use
      # @return [String] the encrypted data
      def encrypt(data, padding: nil, rng: Botan::RNG.new)
        enc = Botan::PK::Encrypt.new(key: self, padding: padding)
        enc.encrypt(data, rng: rng)
      end

      # Verifies a signature using the key.
      #
      # @param data [String] the signature data to verify
      # @param padding [String] the padding method
      # @return [Boolean] true if the signature is valid
      def verify(data:, signature:, padding: nil)
        verify = Botan::PK::Verify.new(key: self, padding: padding)
        verify << data
        verify.check_signature(signature)
      end

      def inspect
        Botan.inspect_ptr(self)
      end

      private

      def export(pem:)
        flags = pem ? 1 : 0
        Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_pubkey_export(@ptr, b, bl, flags)
        }, string: pem)
      end
    end # class
  end # module
end # module


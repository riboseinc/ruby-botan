# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

require 'forwardable'

module Botan
  module PK
    # Private Key
    class PrivateKey
      extend Forwardable
      delegate [:algo, :encrypt, :estimated_strength, :verify] => :public_key
      # @!method algo
      #   @see Botan::PK::PublicKey#algo
      # @!method encrypt
      #   @see Botan::PK::PublicKey#encrypt
      # @!method estimated_strength
      #   @see Botan::PK::PublicKey#estimated_strength
      # @!method verify
      #   @see Botan::PK::PublicKey#verify

      # @api private
      attr_reader :ptr
      # @api private
      #
      # See {generate} and {from_data} instead.
      def initialize(ptr)
        if ptr.null?
          raise Botan::Error, 'PrivateKey received a NULL pointer'
        end
        @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
       end

      # @api private
      def self.destroy(ptr)
        LibBotan.botan_privkey_destroy(ptr)
      end

      # Generates a new key pair.
      #
      # @param algo [String] the public-key algorithm name
      # @param params [String] algorithm-specific parameters
      # @param rng [Botan::RNG] the RNG to use
      # @return [Botan::PK::PrivateKey]
      def self.generate(algo, params: nil, rng: Botan::RNG.new)
        ptr = FFI::MemoryPointer.new(:pointer)
        Botan.call_ffi(:botan_privkey_create, ptr, algo, params, rng.ptr)
        ptr = ptr.read_pointer
        if ptr.null?
          raise Botan::Error, "botan_privkey_create failed"
        end
        PrivateKey.new(ptr)
      end

      # Creates a {PrivateKey} from BER/PEM data.
      #
      # @param data [String] the private key data in a supported format
      # @return [Botan::PK::PrivateKey]
      def self.from_data(data, password: nil, rng: Botan::RNG.new)
        ptr = FFI::MemoryPointer.new(:pointer)
        buf = FFI::MemoryPointer.from_data(data)
        Botan.call_ffi(:botan_privkey_load, ptr, rng.ptr, buf, buf.size, password)
        PrivateKey.new(ptr.read_pointer)
      end

      # Returns the {PublicKey} portion of the key pair.
      #
      # @return [Botan::PK::PublicKey]
      def public_key
        pubkey_ptr = FFI::MemoryPointer.new(:pointer)
        Botan.call_ffi(:botan_privkey_export_pubkey, pubkey_ptr, @ptr)
        PublicKey.new(pubkey_ptr.read_pointer)
      end

      # Exports the *unencrypted* key with PEM encoding.
      #
      # @return [String]
      def export_pem
        export(pem: true)
      end

      # Exports the *unencrypted* key with DER encoding.
      #
      # @return [String]
      def export_der
        export(pem: false)
      end

      # Exports the encrypted key with PEM encoding.
      #
      # @param password [String] the password for encrypting/decrypting
      # @param cipher [String] the name of the cipher to use
      # @param pbkdf [String] the name of the PBKDF algorithm to use
      # @param iterations [Integer] the number of iterations for PBKDF
      # @param rng [Botan::RNG] the RNG to use
      # @return [String]
      def export_encrypted_pem(password:,
                               cipher: nil,
                               pbkdf: nil,
                               iterations: Botan::DEFAULT_KDF_ITERATIONS,
                               rng: Botan::RNG.new)
        export_encrypted(password: password,
                         pem: true,
                         cipher: cipher,
                         pbkdf: pbkdf,
                         iterations: iterations,
                         rng: rng)
      end

      # Exports the encrypted key with DER encoding.
      #
      # @param password [String] the password for encrypting/decrypting
      # @param cipher [String] the name of the cipher to use
      # @param pbkdf [String] the name of the PBKDF algorithm to use
      # @param iterations [Integer] the number of iterations for PBKDF
      # @param rng [Botan::RNG] the RNG to use
      # @return [String]
      def export_encrypted_der(password:,
                               cipher: nil,
                               pbkdf: nil,
                               iterations: Botan::DEFAULT_KDF_ITERATIONS,
                               rng: Botan::RNG.new)
        export_encrypted(password: password,
                         pem: true,
                         cipher: cipher,
                         pbkdf: pbkdf,
                         iterations: iterations,
                         rng: rng)
      end

      # Exports the encrypted key with PEM encoding, using a timed PBKDF.
      #
      # @param password [String] the password for encrypting/decrypting
      # @param milliseconds [Integer] the minimum number of milliseconds to
      #   run the PBKDF.
      # @param cipher [String] the name of the cipher to use
      # @param pbkdf [String] the name of the PBKDF algorithm to use
      # @param rng [Botan::RNG] the RNG to use
      # @return [Hash<Symbol>]
      #   * :iterations [Integer] the iteration count used
      #   * :data [String] the PEM-encoded key
      def export_encrypted_pem_timed(password:,
                                     milliseconds:,
                                     cipher: nil,
                                     pbkdf: nil,
                                     rng: Botan::RNG.new)
        export_encrypted_timed(password: password,
                               pem: true,
                               milliseconds: milliseconds,
                               cipher: cipher,
                               pbkdf: pbkdf,
                               rng: rng)
      end

      # Exports the encrypted key with DER encoding, using a timed PBKDF.
      #
      # @param password [String] the password for encrypting/decrypting
      # @param milliseconds [Integer] the minimum number of milliseconds to
      #   run the PBKDF.
      # @param cipher [String] the name of the cipher to use
      # @param pbkdf [String] the name of the PBKDF algorithm to use
      # @param rng [Botan::RNG] the RNG to use
      # @return [Hash<Symbol>]
      #   * :iterations [Integer] the iteration count used
      #   * :data [String] the DER-encoded key
      def export_encrypted_der_timed(password:,
                                     milliseconds:,
                                     cipher: nil,
                                     pbkdf: nil,
                                     rng: Botan::RNG.new)
        export_encrypted_timed(password: password,
                               pem: false,
                               milliseconds: milliseconds,
                               cipher: cipher,
                               pbkdf: pbkdf,
                               rng: rng)
      end

      # Checks whether the key appears to be valid.
      #
      # @param rng [Botan::RNG] the RNG to use
      # @param thorough [Boolean] whether to perform more thorough checks
      #   that may be slower
      # @return [Boolean] true if the key appears to be valid
      def valid?(rng=nil, thorough=false)
        rng ||= Botan::RNG.new
        flags = thorough ? 1 : 0
        rc = LibBotan.botan_privkey_check_key(@ptr, rng.ptr, flags)
        rc == 0
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
        Botan.call_ffi(:botan_privkey_get_field, mp, @ptr, field)
        hex_str = Botan.call_ffi_with_buffer(lambda {|b,bl|
          LibBotan.botan_mp_to_str(mp, 16, b, bl)
        }, string: true)
        hex_str.hex
      ensure
        LibBotan.botan_mp_destroy(mp) if mp and not mp.null?
      end

      # Decrypts data using the key.
      #
      # @param data [String] the data to decrypt
      # @param padding [String] the padding method to use
      # @return [String] the decrypted data
      def decrypt(data, padding: nil)
        dec = Botan::PK::Decrypt.new(private_key: self, padding: padding)
        dec.decrypt(data)
      end

      # Creates a signature using the key.
      #
      # @param data [String] the data to sign
      # @param padding [String] the padding method
      # @param rng [Botan::RNG] the RNG to use
      # @return [String] the generated signature
      def sign(data, padding: nil, rng: Botan::RNG.new)
        sign = Botan::PK::Sign.new(private_key: self, padding: padding)
        sign << data
        sign.finish(rng)
      end

      def inspect
        Botan.inspect_ptr(self)
      end

      private

      def export(pem:)
        flags = pem ? 1 : 0
        Botan.call_ffi_with_buffer(lambda {|b, bl|
          LibBotan.botan_privkey_export(@ptr, b, bl, flags)
        }, string: pem)
      end

      def export_encrypted(password:,
                           pem: true,
                           cipher: nil,
                           pbkdf: nil,
                           iterations: Botan::DEFAULT_KDF_ITERATIONS,
                           rng: Botan::RNG.new)
        flags = pem ? 1 : 0
        Botan.call_ffi_with_buffer(lambda {|b, bl|
          LibBotan.botan_privkey_export_encrypted_pbkdf_iter(
            @ptr, b, bl, rng.ptr, password, iterations,
            cipher, pbkdf, flags)
        }, string: pem)
      end

      def export_encrypted_timed(password:,
                                 milliseconds:,
                                 pem: true,
                                 cipher: nil,
                                 pbkdf: nil,
                                 rng: Botan::RNG.new)
        flags = pem ? 1 : 0
        iterations_ptr = FFI::MemoryPointer.new(:size_t)
        data = Botan.call_ffi_with_buffer(lambda {|b, bl|
          LibBotan.botan_privkey_export_encrypted_pbkdf_msec(
            @ptr, b, bl, rng.ptr, password, milliseconds,
            iterations_ptr, cipher, pbkdf, flags)
        }, string: pem)
        {data: data, iterations: iterations_ptr.read(:size_t)}
      end
    end # class
  end # module
end # module


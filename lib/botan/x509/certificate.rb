# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'date'
require 'ffi'

require 'botan/error'
require 'botan/ffi/libbotan'
require 'botan/pk/publickey'
require 'botan/utils'

module Botan
  module X509
    class Certificate
      def initialize(ptr)
        if ptr.null?
          raise Botan::Error, 'X509::Certificate received a NULL pointer'
        end
        @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      end

      def self.destroy(ptr)
        LibBotan.botan_x509_cert_destroy(ptr)
      end

      def self.from_file(filename)
        ptr = FFI::MemoryPointer.new(:pointer)
        Botan.call_ffi(:botan_x509_cert_load_file, ptr, filename)
        Certificate.new(ptr.read_pointer)
      end

      def self.from_data(data)
        ptr = FFI::MemoryPointer.new(:pointer)
        buf = FFI::MemoryPointer.from_data(data)
        Botan.call_ffi(:botan_x509_cert_load, ptr, buf, buf.size)
        Certificate.new(ptr.read_pointer)
      end

      def time_starts
        time = Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_x509_cert_get_time_starts(@ptr, b, bl)
        }, guess: 16, string: true)
        case time.size
        when 13
          ::DateTime.strptime(time, '%y%m%d%H%M%SZ')
        when 15
          ::DateTime.strptime(time, '%Y%m%d%H%M%SZ')
        else
          raise Botan::Error, 'X509::Certificate time_starts invalid format'
        end
      end

      def time_expires
        time = Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_x509_cert_get_time_expires(@ptr, b, bl)
        }, guess: 16, string: true)
        case time.size
        when 13
          DateTime.strptime(time, '%y%m%d%H%M%SZ')
        when 15
          DateTime.strptime(time, '%Y%m%d%H%M%SZ')
        else
          raise Botan::Error, 'X509::Certificate time_expires invalid format'
        end
      end

      def to_s
        Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_x509_cert_to_string(@ptr, b, bl)
        }, string: true)
      end

      def fingerprint(hash_algo = 'SHA-256')
        n = Botan::Digest.new(hash_algo).length * 3
        Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_x509_cert_get_fingerprint(@ptr, hash_algo, b, bl)
        }, guess: n, string: true)
      end

      def serial_number
        Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_x509_cert_get_serial_number(@ptr, b, bl)
        })
      end

      def authority_key_id
        Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_x509_cert_get_authority_key_id(@ptr, b, bl)
        })
      end

      def subject_key_id
        Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_x509_cert_get_subject_key_id(@ptr, b, bl)
        })
      end

      def subject_public_key_bits
        Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_x509_cert_get_public_key_bits(@ptr, b, bl)
        })
      end

      def subject_public_key
        ptr = FFI::MemoryPointer.new(:pointer)
        Botan.call_ffi(:botan_x509_cert_get_public_key, @ptr, ptr)
        pub = ptr.read_pointer
        if pub.null?
          raise Botan::Error, 'botan_x509_cert_get_public_key returned NULL'
        end
        Botan::PK::PublicKey.new(pub)
      end

      def issuer_info(key, index = 0)
        Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_x509_cert_get_issuer_dn(@ptr, key, index, b, bl)
        }, string: true)
      end

      def subject_info(key, index = 0)
        Botan.call_ffi_with_buffer(lambda { |b, bl|
          LibBotan.botan_x509_cert_get_subject_dn(@ptr, key, index, b, bl)
        }, string: true)
      end

      def allowed_usage?(usage)
        rc = Botan.call_ffi_rc(:botan_x509_cert_allowed_usage,
                               @ptr, usage)
        rc.zero?
      end

      def inspect
        Botan.inspect_ptr(self)
      end
    end # class
  end # module
end # module


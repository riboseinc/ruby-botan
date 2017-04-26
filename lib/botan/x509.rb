require 'date'

module Botan
  class X509Cert
    def initialize(ptr)
      @ptr = ptr
      raise if @ptr.null?
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan.botan_x509_cert_destroy(ptr)
    end

    def self.load_file(filename)
      ptr = FFI::MemoryPointer.new(:pointer)
      rc = LibBotan.botan_x509_cert_load_file(ptr, filename)
      raise if rc != 0
      X509Cert.new(ptr.read_pointer)
    end

    def self.load(bytes)
      ptr = FFI::MemoryPointer.new(:pointer)
      buf = FFI::MemoryPointer.new(:uint8, bytes.bytesize)
      buf.write_bytes(bytes)
      rc = LibBotan.botan_x509_cert_load(ptr, buf, buf.size)
      raise if rc != 0
      X509Cert.new(ptr.read_pointer)
    end

    def time_starts
      time = Botan.call_ffi_returning_string(16, lambda {|b,bl|
        LibBotan.botan_x509_cert_get_time_starts(@ptr, b, bl)
      })
      case time.size
      when 13
        ::DateTime.strptime(time, '%y%m%d%H%M%SZ')
      when 15
        ::DateTime.strptime(time, '%Y%m%d%H%M%SZ')
      else
        raise
      end
    end

    def time_expires
      time = Botan.call_ffi_returning_string(16, lambda {|b,bl|
        LibBotan.botan_x509_cert_get_time_expires(@ptr, b, bl)
      })
      case time.size
      when 13
        DateTime.strptime(time, '%y%m%d%H%M%SZ')
      when 15
        DateTime.strptime(time, '%Y%m%d%H%M%SZ')
      else
        raise
      end
    end

    def to_s
      Botan.call_ffi_returning_string(0, lambda {|b,bl|
        LibBotan.botan_x509_cert_to_string(@ptr, b, bl)
      })
    end

    def fingerprint(hash_algo='SHA-256')
      n = Botan::Hash.new(hash_algo).output_length * 3
      Botan.call_ffi_returning_string(n, lambda {|b,bl|
        LibBotan.botan_x509_cert_get_fingerprint(@ptr, hash_algo, b, bl)
      })
    end

    def serial_number
      Botan.call_ffi_returning_vec(0, lambda {|b,bl|
        LibBotan.botan_x509_cert_get_serial_number(@ptr, b, bl)
      })
    end

    def authority_key_id
      Botan.call_ffi_returning_vec(0, lambda {|b,bl|
        LibBotan.botan_x509_cert_get_authority_key_id(@ptr, b, bl)
      })
    end

    def subject_key_id
      Botan.call_ffi_returning_vec(0, lambda {|b,bl|
        LibBotan.botan_x509_cert_get_subject_key_id(@ptr, b, bl)
      })
    end

    def subject_public_key_bits
      Botan.call_ffi_returning_vec(0, lambda {|b,bl|
        LibBotan.botan_x509_cert_get_public_key_bits(@ptr, b, bl)
      })
    end

    def subject_public_key
      ptr = FFI::MemoryPointer.new(:pointer)
      rc = LibBotan.botan_x509_cert_get_public_key(@ptr, ptr)
      raise if rc != 0
      pub = ptr.read_pointer
      raise if pub.null?
      Botan::PK::PublicKey.new(pub)
    end

    def subject_info(key, index)
      Botan.call_ffi_returning_string(0, lambda {|b,bl|
        LibBotan.botan_x509_cert_get_subject_dn(@ptr, key, index, b, bl)
      })
    end
  end # class
end # module


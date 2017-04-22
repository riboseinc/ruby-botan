require 'date'

module Botan
  class X509Cert
    def initialize(filename=nil, buf=nil)
      raise unless filename or buf
      raise if filename and buf
      ptr = FFI::MemoryPointer.new(:pointer)
      if filename
        rc = LibBotan.botan_x509_cert_load_file(ptr, filename)
      else
        buf_mem = FFI::MemoryPointer.new(:uint8, buf.bytesize)
        buf_mem.write_bytes(buf)
        rc = LibBotan.botan_x509_cert_load(ptr, buf_mem, buf_mem.size)
      end
      raise if rc != 0
      @ptr = ptr.read_pointer
      raise if @ptr.null?
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan.botan_x509_cert_destroy(ptr)
    end

    def time_starts
      time = Botan.call_fn_returning_string(16, lambda {|b,bl| LibBotan.botan_x509_cert_get_time_starts(@ptr, b, bl)})
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
      time = Botan.call_fn_returning_string(16, lambda {|b,bl| LibBotan.botan_x509_cert_get_time_expires(@ptr, b, bl)})
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
      Botan.call_fn_returning_string(0, lambda {|b,bl| LibBotan.botan_x509_cert_to_string(@ptr, b, bl)})
    end

    def fingerprint(hash_algo='SHA-256')
      n = Botan::Hash.new(hash_algo).output_length * 3
      Botan.call_fn_returning_string(n, lambda {|b,bl| LibBotan.botan_x509_cert_get_fingerprint(@ptr, hash_algo, b, bl)})
    end

    def serial_number
      Botan.call_fn_returning_vec(0, lambda {|b,bl| LibBotan.botan_x509_cert_get_serial_number(@ptr, b, bl)})
    end

    def authority_key_id
      Botan.call_fn_returning_vec(0, lambda {|b,bl| LibBotan.botan_x509_cert_get_authority_key_id(@ptr, b, bl)})
    end

    def subject_key_id
      Botan.call_fn_returning_vec(0, lambda {|b,bl| LibBotan.botan_x509_cert_get_subject_key_id(@ptr, b, bl)})
    end

    def subject_public_key_bits
      Botan.call_fn_returning_vec(0, lambda {|b,bl| LibBotan.botan_x509_cert_get_public_key_bits(@ptr, b, bl)})
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
      Botan.call_fn_returning_string(0, lambda {|b,bl| LibBotan.botan_x509_cert_get_subject_dn(@ptr, key, index, b, bl)})
    end
  end # class
end # module


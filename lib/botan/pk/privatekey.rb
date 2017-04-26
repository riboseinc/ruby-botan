module Botan
  module PK
    class PrivateKey
      attr_reader :ptr
      def initialize(ptr)
        @ptr = ptr
        raise if @ptr.null?
        @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
       end

      def self.destroy(ptr)
        LibBotan.botan_privkey_destroy(ptr)
      end

      def self.generate(alg, param, rng)
        ptr = FFI::MemoryPointer.new(:pointer)
        case alg
        when 'rsa'
          rc = LibBotan.botan_privkey_create_rsa(ptr, rng.ptr, param)
        when 'ecdsa'
          rc = LibBotan.botan_privkey_create_ecdsa(ptr, rng.ptr, param)
        when 'ecdh'
          rc = LibBotan.botan_privkey_create_ecdh(ptr, rng.ptr, param)
        when 'mce', 'mceliece'
          rc = LibBotan.botan_privkey_create_mceliece(ptr, rng.ptr, param[0], param[1])
        else
          raise
        end
        raise if rc != 0
        ptr = ptr.read_pointer
        raise if ptr.null?
        PrivateKey.new(ptr)
      end

      def self.load(bytes, rng, password)
        ptr = FFI::MemoryPointer.new(:pointer)
        buf = FFI::MemoryPointer.new(:uint8, bytes.bytesize)
        buf.write_bytes(bytes)
        rc = LibBotan.botan_privkey_load(ptr, rng.ptr, buf, buf.size, password)
        raise if rc != 0
        PrivateKey.new(ptr.read_pointer)
      end

      def public_key
        pubkey_ptr = FFI::MemoryPointer.new(:pointer)
        rc = LibBotan.botan_privkey_export_pubkey(pubkey_ptr, @ptr)
        raise if rc != 0
        PublicKey.new(pubkey_ptr.read_pointer)
      end

      def export(pem=false)
        flags = pem ? 1 : 0
        if pem
          Botan.call_ffi_returning_string(4096, lambda {|b, bl|
            LibBotan.botan_privkey_export(@ptr, b, bl, flags)
          })
        else
          Botan.call_ffi_returning_vec(4096, lambda {|b, bl|
            LibBotan.botan_privkey_export(@ptr, b, bl, flags)
          })
        end
      end
    end # class
  end # module
end # module


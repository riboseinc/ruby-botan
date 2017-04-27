module Botan
  module PK
    class PrivateKey
      attr_reader :ptr
      def initialize(ptr)
        @ptr = ptr
        if @ptr.null?
          raise Botan::Error, 'PrivateKey received a NULL pointer'
        end
        @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
       end

      def self.destroy(ptr)
        LibBotan.botan_privkey_destroy(ptr)
      end

      def self.generate(alg, param, rng)
        ptr = FFI::MemoryPointer.new(:pointer)
        case alg
        when 'rsa'
          Botan.call_ffi(:botan_privkey_create_rsa, ptr, rng.ptr, param)
        when 'ecdsa'
          Botan.call_ffi(:botan_privkey_create_ecdsa, ptr, rng.ptr, param)
        when 'ecdh'
          Botan.call_ffi(:botan_privkey_create_ecdh, ptr, rng.ptr, param)
        when 'mce', 'mceliece'
          Botan.call_ffi(:botan_privkey_create_mceliece, ptr, rng.ptr, param[0], param[1])
        else
          raise Botan::Error, "Invalid algorithm #{alg}"
        end
        ptr = ptr.read_pointer
        if ptr.null?
          raise Botan::Error, "botan_privkey_create_#{alg} failed"
        end
        PrivateKey.new(ptr)
      end

      def self.from_data(data, password:, rng: Botan::RNG.new)
        ptr = FFI::MemoryPointer.new(:pointer)
        buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
        buf.write_bytes(data)
        Botan.call_ffi(:botan_privkey_load, ptr, rng.ptr, buf, buf.size, password)
        PrivateKey.new(ptr.read_pointer)
      end

      def public_key
        pubkey_ptr = FFI::MemoryPointer.new(:pointer)
        Botan.call_ffi(:botan_privkey_export_pubkey, pubkey_ptr, @ptr)
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

      def valid?(rng=nil, thorough=false)
        rng ||= Botan::RNG.new
        flags = thorough ? 1 : 0
        rc = LibBotan.botan_privkey_check_key(@ptr, rng.ptr, flags)
        rc == 0
      end

      def get_field(field)
        mp = nil
        mp_ptr = FFI::MemoryPointer.new(:pointer)
        Botan.call_ffi(:botan_mp_init, mp_ptr)
        mp = mp_ptr.read_pointer
        Botan.call_ffi(:botan_privkey_get_field, mp, @ptr, field)
        hex_str = Botan.call_ffi_returning_string(0, lambda {|b,bl|
          LibBotan.botan_mp_to_str(mp, 16, b, bl)
        })
        hex_str.hex
      ensure
        LibBotan.botan_mp_destroy(mp) if mp and not mp.null?
      end
    end # class
  end # module
end # module


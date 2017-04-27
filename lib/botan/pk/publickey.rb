module Botan
  module PK
    class PublicKey
      attr_reader :ptr
      def initialize(ptr)
        @ptr = ptr
        if @ptr.null?
          raise Botan::Error, 'PublicKey received a NULL pointer'
        end
        @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
      end

      def self.destroy(ptr)
        LibBotan.botan_pubkey_destroy(ptr)
      end

      def self.from_data(data)
        ptr = FFI::MemoryPointer.new(:pointer)
        buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
        buf.write_bytes(data)
        Botan.call_ffi(:botan_pubkey_load, ptr, buf, buf.size)
        PublicKey.new(ptr.read_pointer)
      end

      def estimated_strength
        strength_ptr = FFI::MemoryPointer.new(:size_t)
        Botan.call_ffi(:botan_pubkey_estimated_strength, @ptr, strength_ptr)
        strength_ptr.read(:size_t)
      end

      def algo_name
        Botan.call_ffi_with_buffer(lambda {|b, bl|
          LibBotan.botan_pubkey_algo_name(@ptr, b, bl)
        }, guess: 32, string: true)
      end

      def export_pem
        export(pem: true)
      end

      def export_der
        export(pem: false)
      end

      def to_s
        export_pem
      end

      def fingerprint(hash='SHA-256')
        n = Hash.new(hash).output_length
        buf = FFI::MemoryPointer.new(:uint8, n)
        buf_len_ptr = FFI::MemoryPointer.new(:size_t)
        buf_len_ptr.write(:size_t, n)
        Botan.call_ffi(:botan_pubkey_fingerprint, @ptr, hash, buf, buf_len_ptr)
        data = buf.read_bytes(buf_len_ptr.read(:size_t))
        Botan.hex_encode(data)
      end

      def valid?(rng=nil, thorough=false)
        rng ||= Botan::RNG.new
        flags = thorough ? 1 : 0
        rc = LibBotan.botan_pubkey_check_key(@ptr, rng.ptr, flags)
        rc == 0
      end

      def get_field(field)
        mp = nil
        mp_ptr = FFI::MemoryPointer.new(:pointer)
        Botan.call_ffi(:botan_mp_init, mp_ptr)
        mp = mp_ptr.read_pointer
        Botan.call_ffi(:botan_pubkey_get_field, mp, @ptr, field)
        hex_str = Botan.call_ffi_with_buffer(lambda {|b,bl|
          LibBotan.botan_mp_to_str(mp, 16, b, bl)
        }, string: true)
        hex_str.hex
      ensure
        LibBotan.botan_mp_destroy(mp) if mp and not mp.null?
      end

      def encrypt(data, padding: nil, rng: Botan::RNG.new)
        enc = Botan::PK::Encrypt.new(public_key: self, padding: padding)
        enc.encrypt(data, rng: rng)
      end

      def verify(data:, signature:, padding: nil)
        verify = Botan::PK::Verify.new(public_key: self, padding: padding)
        verify << data
        verify.check_signature(signature)
      end

      private

      def export(pem:)
        flags = pem ? 1 : 0
        Botan.call_ffi_with_buffer(lambda {|b, bl|
          LibBotan.botan_pubkey_export(@ptr, b, bl, flags)
        }, string: pem)
      end
    end # class
  end # module
end # module


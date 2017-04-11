module Botan
  module PK
    class PrivateKey
      attr_reader :ptr
      def initialize(alg, param, rng)
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
        @ptr = ptr.read_pointer
        raise if @ptr.null?
        @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
       end

      def self.destroy(ptr)
        LibBotan.botan_privkey_destroy(ptr)
      end

      def public_key
        pubkey_ptr = FFI::MemoryPointer.new(:pointer)
        rc = LibBotan.botan_privkey_export_pubkey(pubkey_ptr, @ptr)
        raise if rc != 0
        PublicKey.new(pubkey_ptr.read_pointer)
      end

      def export
        call_fn_returning_vec(4096, lambda {|b, bl| LibBotan.botan_privkey_export(@ptr, b, bl)})
      end
    end # class
  end # module
end # module


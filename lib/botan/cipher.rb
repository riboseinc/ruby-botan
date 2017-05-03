module Botan
  class Cipher
    def initialize(algo, encrypt:)
      flags = encrypt ? 0 : 1
      cipher_ptr = FFI::MemoryPointer.new(:pointer)
      Botan.call_ffi(:botan_cipher_init, cipher_ptr, algo, flags)
      @ptr = cipher_ptr.read_pointer
      if @ptr.null?
        raise Botan::Error, 'botan_cipher_init returned NULL'
      end
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def self.destroy(ptr)
      LibBotan.botan_cipher_destroy(ptr)
    end

    def self.encryption(algo)
      Cipher.new(algo, encrypt: true)
    end

    def self.decryption(algo)
      Cipher.new(algo, encrypt: false)
    end

    def default_nonce_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_cipher_get_default_nonce_length, @ptr, length_ptr)
      length_ptr.read(:size_t)
    end

    def update_granularity
      gran_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_cipher_get_update_granularity, @ptr, gran_ptr)
      gran_ptr.read(:size_t)
    end

    def key_length_min
      key_lengths[0]
    end

    def key_length_max
      key_lengths[1]
    end

    def tag_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_cipher_get_tag_length, @ptr, length_ptr)
      length_ptr.read(:size_t)
    end

    def authenticated?
      tag_length > 0
    end

    def valid_nonce_length?(nonce_len)
      rc = Botan.call_ffi_rc(:botan_cipher_valid_nonce_length, @ptr, nonce_len)
      return (rc == 1) ? true : false
    end

    def clear
      Botan.call_ffi(:botan_cipher_clear, @ptr)
    end

    def set_key(key)
      key_buf = FFI::MemoryPointer.new(:uint8, key.bytesize)
      key_buf.write_bytes(key)
      Botan.call_ffi(:botan_cipher_set_key, @ptr, key_buf, key_buf.size)
    end

    def set_assoc_data(ad)
      ad_buf = FFI::MemoryPointer.new(:uint8, ad.bytesize)
      ad_buf.write_bytes(ad)
      Botan.call_ffi(:botan_cipher_set_associated_data, @ptr, ad_buf, ad.size)
    end

    def start(nonce)
      nonce_buf = FFI::MemoryPointer.from_data(nonce)
      Botan.call_ffi(:botan_cipher_start, @ptr, nonce_buf, nonce_buf.size)
    end

    def update(data)
      _update(data, final: false)
    end

    def finish(data=nil)
      _update(data, final: true)
    end

    private

    def key_lengths
      kmin_ptr = FFI::MemoryPointer.new(:size_t)
      kmax_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_cipher_query_keylen, @ptr, kmin_ptr, kmax_ptr)
      return [kmin_ptr.read(:size_t), kmax_ptr.read(:size_t)]
    end

    def _update(data, final:)
      inp = data ? data : ''
      flags = final ? 1 : 0
      out_buf_size = inp.bytesize + (final ? tag_length : 0)
      # FIXME botan currently lacks a way of determining the size required
      # here, taking in to account padding mechanism, etc.
      out_buf_size += 128
      out_buf = FFI::MemoryPointer.new(:uint8, out_buf_size)
      out_written_ptr = FFI::MemoryPointer.new(:size_t)
      input_buf = FFI::MemoryPointer.from_data(inp)
      inp_consumed_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_cipher_update, @ptr, flags, out_buf, out_buf.size,
                           out_written_ptr, input_buf, input_buf.size,
                           inp_consumed_ptr)
      if inp_consumed_ptr.read(:size_t) != inp.bytesize
        raise Botan::Error, 'botan_cipher_update did not consume all input'
      end
      out_buf.read_bytes(out_written_ptr.read(:size_t))
    end
  end # class
end # module


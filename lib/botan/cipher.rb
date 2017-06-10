module Botan
  # Cipher
  #
  # == Examples
  # === examples/cipher.rb
  # {include:file:examples/cipher.rb}
  #
  class Cipher
    # Prefer the shortcuts {encryption} and {decryption} instead.
    #
    # @param algo [String] the algorithm to use (example: AES-128/CTR-BE)
    # @param encrypt [Boolean] true if this will be used for encryption,
    #                          false if it will be used for decryption.
    def initialize(algo, encrypt:)
      flags = encrypt ? 0 : 1
      ptr = FFI::MemoryPointer.new(:pointer)
      Botan.call_ffi(:botan_cipher_init, ptr, algo, flags)
      ptr = ptr.read_pointer
      if ptr.null?
        raise Botan::Error, 'botan_cipher_init returned NULL'
      end
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
    end

    # @api private
    def self.destroy(ptr)
      LibBotan.botan_cipher_destroy(ptr)
    end

    # Creates a new cipher instance for encryption.
    #
    # @param algo [String] the algorithm to use (example: AES-128/CTR-BE)
    # @return [Botan::Cipher] the cipher instance
    def self.encryption(algo)
      Cipher.new(algo, encrypt: true)
    end

    # Creates a new cipher instance for decryption.
    #
    # @param algo [String] the algorithm to use (example: AES-128/CTR-BE)
    # @return [Botan::Cipher] the cipher instance
    def self.decryption(algo)
      Cipher.new(algo, encrypt: false)
    end

    # Retrieves the default nonce length for the cipher.
    #
    # @return [Integer]
    def default_nonce_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_cipher_get_default_nonce_length, @ptr, length_ptr)
      length_ptr.read(:size_t)
    end

    # Retrieves the update granularity for the cipher.
    #
    # @return [Integer]
    def update_granularity
      gran_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_cipher_get_update_granularity, @ptr, gran_ptr)
      gran_ptr.read(:size_t)
    end

    # Retrieves the minimum key length for the cipher.
    #
    # @return [Integer]
    def key_length_min
      key_lengths[0]
    end

    # Retrieves the maximum key length for the cipher.
    #
    # @return [Integer]
    def key_length_max
      key_lengths[1]
    end

    # Retrieves the tag length when using AEAD modes.
    #
    # @return [Integer]
    def tag_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_cipher_get_tag_length, @ptr, length_ptr)
      length_ptr.read(:size_t)
    end

    # Determines whether this is an AEAD mode.
    #
    # @return [Boolean] true if this is an AEAD mode
    def authenticated?
      tag_length > 0
    end

    # Checks whether a nonce length is valid for this cipher.
    #
    # @param nonce_len [Integer] the nonce length to check
    # @return [Boolean] true if the provided nonce length is valid
    def valid_nonce_length?(nonce_len)
      rc = Botan.call_ffi_rc(:botan_cipher_valid_nonce_length, @ptr, nonce_len)
      rc == 1
    end

    # Resets the cipher state.
    #
    # @return [self]
    def reset
      Botan.call_ffi(:botan_cipher_clear, @ptr)
      self
    end

    # Sets the key to be used for the cipher.
    #
    # This should generally be the first thing called after
    # creating a new cipher instance (or after reset).
    #
    # @param key [String] the key
    def key=(key)
      key_buf = FFI::MemoryPointer.from_data(key)
      Botan.call_ffi(:botan_cipher_set_key, @ptr, key_buf, key_buf.size)
    end

    # Sets the IV to be used for the cipher.
    #
    # This should generally be called after {#key=} or after
    # {#auth_data=} (if using AEAD).
    #
    # @param iv [String] the IV
    def iv=(iv)
      start(iv)
    end

    # Sets the associated data when using AEAD modes.
    #
    # This should be called *after* {#key=} and before {#iv=}.
    #
    # @param ad [String] the associated data
    def auth_data=(ad)
      ad_buf = FFI::MemoryPointer.from_data(ad)
      Botan.call_ffi(:botan_cipher_set_associated_data, @ptr, ad_buf, ad.size)
    end

    # Process the data (encrypt/decrypt).
    #
    # @param data [String] the data to encrypt or decrypt.
    #   The size should likely be a multiple of {#update_granularity}.
    # @return [String] the ciphertext or plaintext
    def update(data)
      _update(data, final: false)
    end

    # Finalize the message processing.
    #
    # It is perfectly valid to skip {#update} and pass your
    # entire message here.
    #
    # *Note*: Some ciphers may require a final piece of data of
    # a certain size. See minimum_final_size in the Botan documentation.
    #
    # @param data [String] the data, if any
    # @return [String] the ciphertext or plaintext
    def finish(data=nil)
      _update(data, final: true)
    end

    private

    def start(nonce)
      nonce_buf = FFI::MemoryPointer.from_data(nonce)
      Botan.call_ffi(:botan_cipher_start, @ptr, nonce_buf, nonce_buf.size)
    end

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
      consumed = inp_consumed_ptr.read(:size_t)
      if consumed != inp.bytesize
        raise Botan::Error, "botan_cipher_update did not consume all input (#{consumed} out of #{inp.bytesize} bytes)"
      end
      out_buf.read_bytes(out_written_ptr.read(:size_t))
    end
  end # class
end # module


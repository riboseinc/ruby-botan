module Botan
  # Key Derivation Functions
  #
  # == Examples
  # === examples/kdf.rb
  # {include:file:examples/kdf.rb}
  module KDF
    # Derives a key using the given KDF algorithm.
    #
    # @param secret [String] the secret input
    # @param key_length [Integer] the desired length of the key to produce
    # @param label [String] purpose for the derived keying material
    # @param algo [String] the KDF algorithm name
    # @param salt [String] the randomly chosen salt
    # @return [String] the derived key
    def self.kdf(secret:, key_length:,
                 label: '',
                 algo: DEFAULT_KDF_ALGO,
                 salt: RNG.get(DEFAULT_KDF_SALT_LENGTH))
      out_buf = FFI::MemoryPointer.new(:uint8, key_length)

      secret_buf = FFI::MemoryPointer.from_data(secret)
      salt_buf = FFI::MemoryPointer.from_data(salt)
      label_buf = FFI::MemoryPointer.from_data(label)
      Botan.call_ffi(:botan_kdf,
                     algo, out_buf, out_buf.size,
                     secret_buf, secret_buf.size,
                     salt_buf, salt_buf.size,
                     label_buf, label_buf.size)
      out_buf.read_bytes(key_length)
    end

    # Derives a key using the given PBKDF algorithm.
    #
    # @param password [String] the password to derive the key from
    # @param key_length [Integer] the desired length of the key to produce
    # @param algo [String] the PBKDF algorithm name
    # @param iterations [Integer] the number of iterations to use
    # @param salt [String] the randomly chosen salt
    # @return [String] the derived key
    def self.pbkdf(password:, key_length:,
                   algo: DEFAULT_PBKDF_ALGO,
                   iterations: DEFAULT_KDF_ITERATIONS,
                   salt: RNG.get(DEFAULT_KDF_SALT_LENGTH))
      out_buf = FFI::MemoryPointer.new(:uint8, key_length)
      salt_buf = FFI::MemoryPointer.from_data(salt)
      Botan.call_ffi(:botan_pbkdf,
                     algo, out_buf, key_length,
                     password, salt_buf, salt_buf.size, iterations)
      out_buf.read_bytes(key_length)
    end

    # Derives a key using the given PBKDF algorithm.
    #
    # @param password [String] the password to derive the key from
    # @param key_length [Integer] teh desired length of the key to rpoduce
    # @param milliseconds [Integer] the number of milliseconds to run
    # @param algo [String] the PBKDF algorithm name
    # @param salt [String] the randomly chosen salt
    # @return [Hash<Symbol>]
    #   * :iterations [Integer] the iteration count used
    #   * :key [String] the derived key
    def self.pbkdf_timed(password:, key_length:, milliseconds:,
                         algo: DEFAULT_PBKDF_ALGO,
                         salt: RNG.get(DEFAULT_KDF_SALT_LENGTH))
      out_buf = FFI::MemoryPointer.new(:uint8, key_length)
      salt_buf = FFI::MemoryPointer.from_data(salt)
      iterations_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_pbkdf_timed,
                     algo, out_buf, key_length,
                     password, salt_buf, salt_buf.size,
                     milliseconds, iterations_ptr)
      return {iterations: iterations_ptr.read(:size_t),
              key: out_buf.read_bytes(key_length)}
    end
  end # module
end # module


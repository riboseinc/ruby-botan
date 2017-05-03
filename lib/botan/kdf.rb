module Botan
  def self.kdf(secret:, key_len:, label:,
               algo: DEFAULT_KDF_ALGO,
               salt: RNG.get(DEFAULT_KDF_SALT_LENGTH))
    out_buf = FFI::MemoryPointer.new(:uint8, key_len)

    secret_buf = FFI::MemoryPointer.from_data(secret)
    salt_buf = FFI::MemoryPointer.from_data(salt)
    label_buf = FFI::MemoryPointer.from_data(label)
    Botan.call_ffi(:botan_kdf,
                   algo, out_buf, out_buf.size,
                   secret_buf, secret_buf.size,
                   salt_buf, salt_buf.size,
                   label_buf, label_buf.size)
    out_buf.read_bytes(key_len)
  end

  def self.pbkdf(password:, key_len:,
                 algo: DEFAULT_PBKDF_ALGO,
                 iterations: DEFAULT_KDF_ITERATIONS,
                 salt: RNG.get(DEFAULT_KDF_SALT_LENGTH))
    out_buf = FFI::MemoryPointer.new(:uint8, key_len)
    salt_buf = FFI::MemoryPointer.from_data(salt)
    Botan.call_ffi(:botan_pbkdf,
                   algo, out_buf, key_len,
                   password, salt_buf, salt_buf.size, iterations)
    return {salt: salt,
            iterations: iterations,
            key: out_buf.read_bytes(key_len)}
  end

  def self.pbkdf_timed(password:, key_len:, ms_to_run:,
                       algo: DEFAULT_PBKDF_ALGO,
                       salt: RNG.get(DEFAULT_KDF_SALT_LENGTH))
    out_buf = FFI::MemoryPointer.new(:uint8, key_len)
    salt_buf = FFI::MemoryPointer.from_data(salt)
    iterations_ptr = FFI::MemoryPointer.new(:size_t)
    Botan.call_ffi(:botan_pbkdf_timed,
                   algo, out_buf, key_len,
                   password, salt_buf, salt_buf.size,
                   ms_to_run, iterations_ptr)
    return {salt: salt,
            iterations: iterations_ptr.read(:size_t),
            key: out_buf.read_bytes(key_len)}
  end
end # module


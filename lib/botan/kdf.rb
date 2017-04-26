module Botan
  def self.kdf(algo, secret, out_len, salt, label)
    out_buf = FFI::MemoryPointer.new(:uint8, out_len)

    secret_buf = FFI::MemoryPointer.new(:uint8, secret.bytesize)
    secret_buf.write_bytes(secret)

    salt_buf = FFI::MemoryPointer.new(:uint8, salt.bytesize)
    salt_buf.write_bytes(salt)

    label_buf = FFI::MemoryPointer.from_string(label)
    label_buf = FFI::MemoryPointer.new(:uint8, label.bytesize)
    label_buf.write_bytes(label)
    Botan.call_ffi(:botan_kdf,
                   algo, out_buf, out_buf.size,
                   secret_buf, secret_buf.size,
                   salt_buf, salt_buf.size,
                   label_buf, label_buf.size)
    out_buf.read_bytes(out_len)
  end

  def self.pbkdf(algo, password, out_len, iterations=10000, salt=RNG.new.get(12))
    out_buf = FFI::MemoryPointer.new(:uint8, out_len)
    salt_buf = FFI::MemoryPointer.new(:uint8, salt.bytesize)
    salt_buf.write_bytes(salt)
    Botan.call_ffi(:botan_pbkdf,
                   algo, out_buf, out_len,
                   password, salt_buf, salt_buf.size, iterations)
    return [salt, iterations, out_buf.read_bytes(out_len)]
  end

  def self.pbkdf_timed(algo, password, out_len, ms_to_run=300, salt=RNG.new.get(12))
    out_buf = FFI::MemoryPointer.new(:uint8, out_len)
    salt_buf = FFI::MemoryPointer.new(:uint8, salt.bytesize)
    salt_buf.write_bytes(salt)
    iterations_ptr = FFI::MemoryPointer.new(:size_t)
    Botan.call_ffi(:botan_pbkdf_timed,
                   algo, out_buf, out_len,
                   password, salt_buf, salt_buf.size,
                   ms_to_run, iterations_ptr)
    return [salt, iterations_ptr.read(:size_t), out_buf.read_bytes(out_len)]
  end
end # module


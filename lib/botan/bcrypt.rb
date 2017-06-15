# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

require 'ffi'

require 'botan/rng'
require 'botan/utils'

module Botan
  # bcrypt password hashing
  #
  # == Examples
  # === examples/bcrypt.rb
  # {include:file:examples/bcrypt.rb}
  #
  module BCrypt
    # Generates a password hash using bcrypt.
    #
    # @param password [String] the password to hash
    # @param work_factor [Integer] the bcrypt work factor
    # @param rng [Botan::RNG] the RNG to use
    # @return [String] the generated password hash
    def self.hash(password, work_factor: 10, rng: Botan::RNG.new)
      out_len = 64
      out_buf = FFI::MemoryPointer.new(:uint8, out_len)
      flags = 0
      out_len_ptr = FFI::MemoryPointer.new(:size_t)
      out_len_ptr.write(:size_t, out_len)
      Botan.call_ffi(:botan_bcrypt_generate,
                     out_buf, out_len_ptr,
                     password, rng.ptr, work_factor, flags)
      result = out_buf.read_bytes(out_len_ptr.read(:size_t))
      result = result[0...-1] if result[-1] == "\x00"
      result
    end

    # Checks a password against a bcrypt hash.
    #
    # @param password [String] the password to hash
    # @param phash [String] the bcrypt hash
    # @return [Boolean] true if the provided password is correct
    def self.valid?(password:, phash:)
      rc = Botan.call_ffi_rc(:botan_bcrypt_is_valid, password, phash)
      return rc == 0
    end
  end # module
end # module


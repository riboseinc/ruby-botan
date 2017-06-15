# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'ffi'

require 'botan/error'
require 'botan/ffi/libbotan'
require 'botan/utils'

module Botan
  # Random Number Generator
  class RNG
    # @api private
    attr_reader :ptr
    # @param rng_type [String] the type of RNG to create
    def initialize(rng_type = nil)
      ptr = FFI::MemoryPointer.new(:pointer)
      Botan.call_ffi(:botan_rng_init, ptr, rng_type)
      ptr = ptr.read_pointer
      raise Botan::Error, 'botan_rng_init returned NULL' if ptr.null?
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
    end

    # @api private
    def self.destroy(ptr)
      LibBotan.botan_rng_destroy(ptr)
    end

    # Retrieves some data from the default RNG.
    #
    # @param length [Integer] the number of bytes to retrieve
    # @return [String]
    def self.get(length)
      RNG.new.get(length)
    end

    # Reseeds the RNG from the system RNG.
    #
    # @param bits [Integer] the number of bits to reseed with
    # @return [self]
    def reseed(bits = 256)
      Botan.call_ffi(:botan_rng_reseed, @ptr, bits)
      self
    end

    # Retrieves some data from the RNG.
    #
    # @param length [Integer] the number of bytes to retrieve
    # @return [String]
    def get(length)
      out_buf = FFI::MemoryPointer.new(:uint8, length)
      Botan.call_ffi(:botan_rng_get, @ptr, out_buf, length)
      out_buf.read_bytes(length)
    end

    def inspect
      Botan.inspect_ptr(self)
    end
  end # class
end # module


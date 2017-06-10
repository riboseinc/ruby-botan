require 'digest'

module Botan
  # Class for calculating message digests using Botan's hash functions.
  #
  # This should behave nearly identically to {::Digest} and {OpenSSL::Digest}.
  # Some differences are:
  #
  # * Algorithm names. Example: OpenSSL expects `RIPEMD160`, Botan
  #   uses `RIPEMD-160`.
  # * OIDs. Not currently supported.
  #
  # == Examples
  # === examples/digest.rb
  # {include:file:examples/digest.rb}
  class Digest < ::Digest::Class
    attr_reader :name
    # @api private
    attr_reader :ptr

    def initialize(algo)
      @name = algo
      flags = 0
      ptr = FFI::MemoryPointer.new(:pointer)
      Botan.call_ffi(:botan_hash_init, ptr, algo, flags)
      @ptr = ptr.read_pointer
      if @ptr.null?
        raise Botan::Error, 'botan_hash_init returned NULL'
      end
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    def initialize_copy(source)
      @name = source.name
      ptr = FFI::MemoryPointer.new(:pointer)
      Botan.call_ffi(:botan_hash_copy_state, ptr, source.ptr)
      @ptr = ptr.read_pointer
      @ptr_auto = FFI::AutoPointer.new(@ptr, self.class.method(:destroy))
    end

    # @api private
    def self.destroy(ptr)
      LibBotan.botan_hash_destroy(ptr)
    end

    {
      sha1:       'SHA-1',
      sha224:     'SHA-224',
      sha256:     'SHA-256',
      sha384:     'SHA-384',
      sha512:     'SHA-512',
      sha512_256: 'SHA-512-256',
      rmd160:     'RIPEMD-160',
      whirlpool:  'Whirlpool',
      md5:        'MD5',
      md4:        'MD4',
      gost3411:   'GOST-34.11',
      adler32:    'Adler32',
      crc24:      'CRC24',
      crc32:      'CRC32',
      sm3:        'SM3'
    }.each {|method_name, algo|
      klass = Class.new(self) {
        define_method(:initialize, ->(data = nil) {super(algo); update(data) if data})
      }
      singleton = (class << klass; self; end)
      singleton.class_eval{
        define_method(:digest){|data| new.digest(data) }
        define_method(:hexdigest){|data| new.hexdigest(data) }
      }
      const_set(method_name.upcase, klass)
    }

    # Retrieve the block length for the hash.
    #
    # @return [Integer]
    def block_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_hash_block_size, @ptr, length_ptr)
      length_ptr.read(:size_t)
    end

    # Retrieve the length of the digest.
    #
    # @return [Integer]
    def digest_length
      length_ptr = FFI::MemoryPointer.new(:size_t)
      Botan.call_ffi(:botan_hash_output_length, @ptr, length_ptr)
      length_ptr.read(:size_t)
    end

    # Adds input to the digest computation.
    #
    # @param [String] data
    # @return [self]
    def update(data)
      Botan.call_ffi(:botan_hash_update, @ptr, data, data.bytesize)
      self
    end

    # Resets the instace back to a clean state, as if no data has
    # been supplied.
    #
    # @return [self]
    def reset
      Botan.call_ffi(:botan_hash_clear, @ptr)
      self
    end

    alias << update

    private

    def finish
      out_buf = FFI::MemoryPointer.new(:uint8, digest_length)
      Botan.call_ffi(:botan_hash_final, @ptr, out_buf)
      out_buf.read_bytes(out_buf.size)
    end
  end # class

  # Returns a Digest subclass by name.
  #
  # @param algo [String] the hash algorithm name
  # @return [Class]
  def Digest(algo)
    Botan::Digest.const_get(algo)
  end

  module_function :Digest
end # module


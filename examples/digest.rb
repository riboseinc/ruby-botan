# frozen_string_literal: true

require 'botan/digest'

md5 = Botan::Digest::MD5.new
md5 << 'some '
md5 << 'data'
puts md5.hexdigest

hash = Botan::Digest.new('Comb4P(SHA-160,RIPEMD-160)')
hash << 'test'
puts Botan.hex_encode(hash.digest)


require 'spec_helper'

# based on ruby/test/openssl/test_digest.rb
describe Botan::Digest do
  context 'OpenSSL compatibility' do
    let(:d1) { Botan::Digest.new('MD5') }
    let(:d2) { Botan::Digest::MD5.new }

    it 'test_digest' do
      null_hex = "d41d8cd98f00b204e9800998ecf8427e"
      null_bin = Botan.hex_decode(null_hex)
      data = "DATA"
      hex = "e44f9e348e41cb272efa87387728571b"
      bin = Botan.hex_decode(hex)
      expect(null_bin).to eql d1.digest
      expect(null_hex).to eql d1.hexdigest
      d1 << data
      expect(bin).to eql d1.digest
      expect(hex).to eql d1.hexdigest
      expect(bin).to eql Botan::Digest::MD5.digest(data)
      expect(hex).to eql Botan::Digest::MD5.hexdigest(data)
    end

    it 'test_eql' do
      expect(d1).to eq d2
      d = d1.clone
      expect(d).to eq d1
    end

    it 'test_info' do
      expect(d1.name).to eql "MD5"
      expect(d2.name).to eql "MD5"
      expect(d1.size).to eql 16
    end

    it 'test_dup' do
      d1.update("DATA")
      expect(d1.name).to eql d1.dup.name
      expect(d1.name).to eql d1.clone.name
      expect(d1.digest).to eql d1.clone.digest
    end

    it 'test_reset' do
      d1.update("DATA")
      dig1 = d1.digest
      d1.reset
      d1.update("DATA")
      dig2 = d1.digest
      expect(dig1).to eql dig2
    end

    it 'test_digest_constants' do
      {
        SHA1:       'SHA-1',
        SHA224:     'SHA-224',
        SHA256:     'SHA-256',
        SHA384:     'SHA-384',
        SHA512:     'SHA-512',
        SHA512_256: 'SHA-512-256',
        RMD160:     'RIPEMD-160',
        WHIRLPOOL:  'Whirlpool',
        MD5:        'MD5',
        MD4:        'MD4',
        GOST3411:   'GOST-34.11',
        ADLER32:    'Adler32',
        CRC24:      'CRC24',
        CRC32:      'CRC32',
        SM3:        'SM3'
      }.each {|class_name, algo|
        expect(Botan::Digest.new(algo)).to_not be_nil
        klass = Botan::Digest.const_get(class_name)
        expect(klass.new).to_not be_nil
      }
    end

    it 'test_098_features' do
      sha224_a = "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"
      sha256_a = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
      sha384_a = "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31"
      sha512_a = "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"

      expect(sha224_a).to eql Botan::Digest::SHA224.hexdigest("a")
      expect(sha256_a).to eql Botan::Digest::SHA256.hexdigest("a")
      expect(sha384_a).to eql Botan::Digest::SHA384.hexdigest("a")
      expect(sha512_a).to eql Botan::Digest::SHA512.hexdigest("a")

      expect(sha224_a).to eql Botan.hex_encode(Botan::Digest::SHA224.digest("a"))
      expect(sha256_a).to eql Botan.hex_encode(Botan::Digest::SHA256.digest("a"))
      expect(sha384_a).to eql Botan.hex_encode(Botan::Digest::SHA384.digest("a"))
      expect(sha512_a).to eql Botan.hex_encode(Botan::Digest::SHA512.digest("a"))
    end
  end
end


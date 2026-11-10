# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'spec_helper'

describe Botan::Aead do
  let(:key) { Botan::RNG.new.get(32) }
  let(:nonce) { Botan::RNG.new.get(12) }
  let(:ad) { 'header' }
  let(:plaintext) { 'aead wrapper plaintext' }

  %w[AES-256/GCM ChaCha20Poly1305 AES-256/GCM-SIV].each do |algo|
    context algo do
      before(:context) do
        major = LibBotan.botan_version_major
        minor = LibBotan.botan_version_minor
        skip 'GCM-SIV requires Botan >= 3.13' if algo == 'AES-256/GCM-SIV' &&
                                                 (major < 3 || (major == 3 && minor < 13))
      end

      it 'round-trips with associated data' do
        blob = described_class.encrypt(algo, key, nonce, plaintext, ad: ad)
        expect(blob.bytesize).to eql plaintext.bytesize + 16
        expect(described_class.decrypt(algo, key, nonce, blob, ad: ad)).to eql plaintext
      end

      it 'round-trips without associated data' do
        blob = described_class.encrypt(algo, key, nonce, plaintext)
        expect(described_class.decrypt(algo, key, nonce, blob)).to eql plaintext
      end

      it 'rejects a tampered blob' do
        blob = described_class.encrypt(algo, key, nonce, plaintext, ad: ad)
        tampered = blob.dup
        tampered[0] = (tampered[0].ord ^ 0x80).chr
        expect do
          described_class.decrypt(algo, key, nonce, tampered, ad: ad)
        end.to raise_error(Botan::Error)
      end

      it 'rejects mismatched associated data' do
        blob = described_class.encrypt(algo, key, nonce, plaintext, ad: ad)
        expect do
          described_class.decrypt(algo, key, nonce, blob, ad: 'other')
        end.to raise_error(Botan::Error)
      end
    end
  end

  context 'RFC 8452 vector through the wrapper (AES-128/GCM-SIV)' do
    before(:context) do
      major = LibBotan.botan_version_major
      minor = LibBotan.botan_version_minor
      skip 'GCM-SIV requires Botan >= 3.13' if major < 3 || (major == 3 && minor < 13)
    end

    it 'matches the published ciphertext and tag' do
      key = Botan.hex_decode('01000000000000000000000000000000')
      nonce = Botan.hex_decode('030000000000000000000000')
      pt = Botan.hex_decode('0100000000000000')
      out = Botan.hex_decode('B5D839330AC7B786578782FFF6013B815B287C22493A364C')
      # Botan (and the RFC) use tag-first for SIV; the wrapper normalizes
      # to tag-last.
      expect(described_class.encrypt('AES-128/GCM-SIV', key, nonce, pt)).to eql(out[16..] + out[0, 16])
      expect(described_class.decrypt('AES-128/GCM-SIV', key, nonce, out[16..] + out[0, 16])).to eql(pt)
    end
  end
end

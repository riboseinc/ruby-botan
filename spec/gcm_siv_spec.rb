# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'spec_helper'

# RFC 8452 AES-GCM-SIV, exercised through the generic cipher wrapper.
# Requires Botan >= 3.13 (the release that implemented RFC 8452).
describe 'AES-GCM-SIV (RFC 8452)' do
  before(:all) do
    skip 'GCM-SIV requires Botan >= 3.13' if LibBotan.botan_version_major < 3 ||
                                             (LibBotan.botan_version_major == 3 && LibBotan.botan_version_minor < 13)
  end

  # Appendix C test vectors. The RFC wire layout is tag (16 bytes)
  # followed by the ciphertext; Botan's Cipher#finish appends the tag
  # to the ciphertext, so the expected Botan output is ct || tag.
  vectors = [
    { algo: 'AES-128/GCM-SIV',
      key: '01000000000000000000000000000000',
      nonce: '030000000000000000000000',
      ad: nil,
      pt: '',
      out: 'DC20E2D83F25705BB49E439ECA56DE25' },
    { algo: 'AES-128/GCM-SIV',
      key: '01000000000000000000000000000000',
      nonce: '030000000000000000000000',
      ad: nil,
      pt: '0100000000000000',
      out: 'B5D839330AC7B786578782FFF6013B815B287C22493A364C' },
    { algo: 'AES-128/GCM-SIV',
      key: '01000000000000000000000000000000',
      nonce: '030000000000000000000000',
      ad: '01',
      pt: '0200000000000000',
      out: '1E6DABA35669F4273B0A1A2560969CDF790D99759ABD1508' },
    { algo: 'AES-256/GCM-SIV',
      key: '0100000000000000000000000000000000000000000000000000000000000000',
      nonce: '030000000000000000000000',
      ad: nil,
      pt: '0100000000000000',
      out: 'C2EF328E5C71C83B843122130F7364B761E0B97427E3DF28' }
  ].freeze

  def h2b(hex)
    [hex].pack('H*')
  end

  vectors.each do |v|
    context v[:algo] do
      let(:enc) { Botan::Cipher.encryption(v[:algo]) }
      let(:dec) { Botan::Cipher.decryption(v[:algo]) }
      let(:key) { h2b(v[:key]) }
      let(:iv) { h2b(v[:nonce]) }
      let(:ad) { v[:ad] && h2b(v[:ad]) }
      let(:pt) { h2b(v[:pt]) }
      let(:out) { h2b(v[:out]) }
      let(:tag) { out[0, 16] }
      let(:ct) { out[16..] }

      it 'encrypts to the RFC vector' do
        enc.auth_data = ad if ad
        enc.key = key
        enc.iv = iv
        # Botan prefixes the tag for SIV modes — identical to the RFC
        # wire layout.
        expect(enc.finish(pt)).to eql(out)
      end

      it 'decrypts the RFC vector' do
        dec.auth_data = ad if ad
        dec.key = key
        dec.iv = iv
        expect(dec.finish(out)).to eql(pt)
      end

      it 'rejects a tampered tag' do
        dec.auth_data = ad if ad
        dec.key = key
        dec.iv = iv
        bad = out.dup.tap { |t| t.setbyte(0, t.getbyte(0) ^ 0x80) }
        expect { dec.finish(bad) }.to raise_error(Botan::Error)
      end
    end
  end
end

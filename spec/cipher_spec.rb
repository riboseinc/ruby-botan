require 'spec_helper'

describe Botan::Cipher do
  context 'AES-128/CTR-BE' do
    let(:enc) { Botan::Cipher.encryption('AES-128/CTR-BE') }
    let(:dec) { Botan::Cipher.decryption('AES-128/CTR-BE') }
    let(:kmin) { enc.key_length_min }
    let(:kmax) { enc.key_length_max }
    let(:iv) { Botan::RNG.new.get(enc.default_nonce_length) }
    let(:key) { Botan::RNG.new.get(kmax) }
    let(:plaintext) { Botan::RNG.new.get(21) }

    it 'has expected default nonce length' do
      expect(enc.default_nonce_length).to eql 0
    end

    it 'does validate nonce lengths' do
      expect(enc.valid_nonce_length?(enc.default_nonce_length)).to eql true
    end

    it 'has expected key lengths' do
      expect(kmin).to eql 16
      expect(kmax).to eql 16
    end

    it 'has expected update granularity' do
      expect(enc.update_granularity).to eql 1
    end

    it 'encrypts and decrypts successfully' do
      enc.key = key
      enc.iv = iv
      expect(enc.update('').bytesize).to eql 0
      ciphertext = enc.finish(plaintext)

      dec.key = key
      dec.iv = iv
      decrypted = dec.finish(ciphertext)

      expect(plaintext).to eql decrypted
    end

    it 'can be cleared and reused' do
      enc.key = key
      enc.iv = iv
      ciphertext = enc.finish(plaintext)

      enc.clear
      enc.key = key
      enc.iv = iv
      expect(enc.finish(plaintext)).to eql ciphertext

      dec.clear
      dec.key = key
      dec.iv = iv
      expect(dec.finish(ciphertext)).to eql plaintext

      dec.clear
      dec.key = key
      dec.iv = iv
      expect(dec.finish(ciphertext)).to eql plaintext
    end

    it 'can be incrementally updated' do
      enc.key = key
      enc.iv = iv
      ciphertext = enc.finish(plaintext)

      enc.clear
      enc.key = key
      enc.iv = iv
      ciphertext2 = enc.update(plaintext[0..-2])
      ciphertext2 += enc.finish(plaintext[-1])
      expect(ciphertext2).to eql ciphertext
    end
  end
  context 'AES-128/CBC/PKCS7' do
    let(:mode) { 'AES-128/CBC/PKCS7' }
    let(:enc) { Botan::Cipher.encryption(mode) }
    let(:dec) { Botan::Cipher.decryption(mode) }
    let(:iv) { Botan.hex_decode('9dea7621945988f96491083849b068df') }
    let(:key) { Botan.hex_decode('898be9cc5004ed0fa6e117c9a3099d31') }
    let(:plaintext) { Botan.hex_decode('0397f4f6820b1f9386f14403be5ac16e50213bd473b4874b9bcbf5f318ee686b1d') }

    it 'has expected default nonce length' do
      expect(enc.default_nonce_length).to eql 16
    end

    it 'does validate nonce lengths' do
      expect(enc.valid_nonce_length?(enc.default_nonce_length)).to eql true
    end

    it 'has expected key lengths' do
      expect(enc.key_length_min).to eql 16
      expect(enc.key_length_max).to eql 16
    end

    it 'has expected update granularity' do
      expect(enc.update_granularity).to eql 64
    end

    it 'encrypts and decrypts successfully' do
      enc.key = key
      enc.iv = iv
      ciphertext = enc.finish(plaintext)
      expect(Botan.hex_encode(ciphertext)).to eql 'e232cd6ef50047801ee681ec30f61d53cfd6b0bca02fd03c1b234baa10ea82ac9dab8b960926433a19ce6dea08677e34'

      dec.key = key
      dec.iv = iv
      decrypted = dec.finish(ciphertext)

      expect(plaintext).to eql decrypted
    end
  end
end


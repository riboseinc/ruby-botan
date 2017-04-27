require 'spec_helper'

describe Botan::Cipher do
  context 'AES-128/CTR-BE' do
    let(:enc) { Botan::Cipher.encryption('AES-128/CTR-BE') }
    let(:dec) { Botan::Cipher.decryption('AES-128/CTR-BE') }
    let(:kmin) { enc.key_length[0] }
    let(:kmax) { enc.key_length[1] }
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
      enc.set_key(key)
      enc.start(iv)
      expect(enc.update('').bytesize).to eql 0
      ciphertext = enc.finish(plaintext)

      dec.set_key(key)
      dec.start(iv)
      decrypted = dec.finish(ciphertext)

      expect(plaintext).to eql decrypted
    end

    it 'can be cleared and reused' do
      enc.set_key(key)
      enc.start(iv)
      ciphertext = enc.finish(plaintext)

      enc.clear
      enc.set_key(key)
      enc.start(iv)
      expect(enc.finish(plaintext)).to eql ciphertext

      dec.clear
      dec.set_key(key)
      dec.start(iv)
      expect(dec.finish(ciphertext)).to eql plaintext

      dec.clear
      dec.set_key(key)
      dec.start(iv)
      expect(dec.finish(ciphertext)).to eql plaintext
    end

    it 'can be incrementally updated' do
      enc.set_key(key)
      enc.start(iv)
      ciphertext = enc.finish(plaintext)

      enc.clear
      enc.set_key(key)
      enc.start(iv)
      ciphertext2 = enc.update(plaintext[0..-2])
      ciphertext2 += enc.finish(plaintext[-1])
      expect(ciphertext2).to eql ciphertext
    end
  end
end


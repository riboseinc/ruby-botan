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

      enc.reset
      enc.key = key
      enc.iv = iv
      expect(enc.finish(plaintext)).to eql ciphertext

      dec.reset
      dec.key = key
      dec.iv = iv
      expect(dec.finish(ciphertext)).to eql plaintext

      dec.reset
      dec.key = key
      dec.iv = iv
      expect(dec.finish(ciphertext)).to eql plaintext
    end

    it 'can be incrementally updated' do
      enc.key = key
      enc.iv = iv
      ciphertext = enc.finish(plaintext)

      enc.reset
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

  context 'AES-128/GCM' do
    let(:enc) { Botan::Cipher.encryption('AES-128/GCM') }
    let(:dec) { Botan::Cipher.decryption('AES-128/GCM') }
    let(:key) { Botan::hex_decode('FEFFE9928665731C6D6A8F9467308308') }
    let(:nonce) { Botan::hex_decode('CAFEBABEFACEDBADDECAF888') }
    let(:input) { Botan::hex_decode('D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39') }
    let(:ad) { Botan::hex_decode('FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2') }
    let(:output) { Botan::hex_decode('42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E0915BC94FBC3221A5DB94FAE95AE7121A47') }

    it { expect(enc.authenticated?).to eql true }
    it { expect(dec.authenticated?).to eql true }

    it 'encrypts correctly' do
      enc.key = key
      enc.auth_data = ad
      enc.iv = nonce
      expect(enc.finish(input)).to eql output
    end

    it 'decrypts correctly' do
      dec.key = key
      dec.auth_data = ad
      dec.iv = nonce
      expect(dec.finish(output)).to eql input
    end

    it 'raises an error with modified message' do
      dec.key = key
      dec.auth_data = ad
      dec.iv = nonce
      bad_output = output
      bad_output[bad_output.bytesize / 2] = 0xAA.chr
      expect { dec.finish(bad_output) }.to raise_error Botan::Error
    end

    it 'raises an error with modified nonce' do
      dec.key = key
      dec.auth_data = ad
      bad_nonce = nonce
      bad_nonce[bad_nonce.bytesize / 2] = 0xAA.chr
      dec.iv = nonce
      expect { dec.finish(output) }.to raise_error Botan::Error
    end

    it 'raises an error with modified ad' do
      dec.key = key
      bad_ad = ad
      bad_ad[bad_ad.bytesize / 2] = 0xAA.chr
      dec.auth_data = bad_ad
      dec.iv = nonce
      expect { dec.finish(output) }.to raise_error Botan::Error
    end
  end
end


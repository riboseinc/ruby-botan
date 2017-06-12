require 'spec_helper'

describe 'Public Key Operations' do
  let(:key) { Botan::PK::PrivateKey.from_data(File.read('spec/data/private_key.pem')) }
  let(:plaintext) { Botan.hex_decode('0ecae8d6cf5567272c4d5f5163aafde6068308693d022255dc047fb302a559612e116e995e351b1d27e0fa75d61c9419b71d042eae5d38841f1ffa72797e23cffa6dde2aaa00ba183afd4b0ac25272f7cbe8aa3cae1035bb6fae423d30078e29e0a81707ce7696e9cd63d5f60ad170a03b54c3a3b4c2fbab4c715ac14fe38f52') }
  let(:ciphertext) { Botan.hex_decode('980ed7695ca93cf5279826d927339e52ab3711b47fe2dbe952ff09ad878ea3b1d77b19ac8e9f0c0f5656798bac52b61f5c20fa9fa188c74f5977a6a63600807d4ba5c1f5638b5ff11da058fabfd239bb0d56c3cc4d1fc6b081fff9c5dd6035f7eb651b6a1c88d009abb0a947690e5e91897113168923b017dd53a79bc84accf9') }
  let(:signature) { Botan.hex_decode('96a331c528c32890a2bade3d71e0375b8c310588473d82f619c8094fc5b8d84a5532858b1b72e1a8ded03dbc95f6b5ecc7eb6ecb4eeeaef13e9fcbc3f27dc5e93fd322acf688eccc94498698e6f1dd0544d2835ef3bce3b24cb0b6a15eedf7d7009bbeff13010e2b41dd0d0e87111c529ae66df8b3858306928208f480d5e705') }

  context Botan::PK::Encrypt do
    let(:enc) { Botan::PK::Encrypt.new(public_key: key.public_key, padding: 'Raw') }

    it 'responds to inspect' do
      expect(enc.class.instance_methods(false).include?(:inspect)).to be true
      expect(enc.inspect.class).to eql String
      expect(enc.inspect.length).to be >= 1
    end

    it 'encrypts correctly' do
      expect(enc.encrypt(plaintext)).to eql ciphertext
    end
  end

  context Botan::PK::Decrypt do
    let(:dec) { Botan::PK::Decrypt.new(private_key: key, padding: 'Raw') }

    it 'responds to inspect' do
      expect(dec.class.instance_methods(false).include?(:inspect)).to be true
      expect(dec.inspect.class).to eql String
      expect(dec.inspect.length).to be >= 1
    end

    it 'decrypts correctly' do
      expect(dec.decrypt(ciphertext)).to eql plaintext
    end
  end

  context Botan::PK::Sign do
    let(:sign) { Botan::PK::Sign.new(private_key: key, padding: 'Raw') }

    it 'responds to inspect' do
      expect(sign.class.instance_methods(false).include?(:inspect)).to be true
      expect(sign.inspect.class).to eql String
      expect(sign.inspect.length).to be >= 1
    end

    it 'signs correctly' do
      sign << plaintext
      expect(sign.finish).to eql signature
    end
  end

  context Botan::PK::Verify do
    let(:verify) { Botan::PK::Verify.new(public_key: key.public_key, padding: 'Raw') }

    it 'responds to inspect' do
      expect(verify.class.instance_methods(false).include?(:inspect)).to be true
      expect(verify.inspect.class).to eql String
      expect(verify.inspect.length).to be >= 1
    end

    it 'verifies correct data' do
      verify << plaintext
      expect(verify.check_signature(signature)).to be true
    end

    it 'does not verify short data' do
      verify << plaintext[0...-1]
      expect(verify.check_signature(signature)).to be false
    end

    it 'does not verify modified data' do
      plaintext[plaintext.size / 2] = (plaintext[plaintext.size / 2].ord ^ 0xff).chr
      verify << plaintext
      expect(verify.check_signature(signature)).to be false
    end

    it 'does not verify modified signature' do
      signature[signature.size / 2] = (signature[signature.size / 2].ord ^ 0xff).chr
      expect(verify.check_signature(signature)).to be false
    end
  end
end


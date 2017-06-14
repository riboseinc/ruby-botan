# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

require 'spec_helper'

describe 'PK' do
  context 'rsa generation' do
    let(:priv) { Botan::PK::PrivateKey.generate('RSA', params: '1024', rng: Botan::RNG.new) }
    let(:pub) { priv.public_key }
    let(:rng) { Botan::RNG.new }
    let(:symkey) { rng.get(32) }

    it 'passes basic checks' do
      expect(pub.valid?).to eql true
      expect(pub.valid?(rng)).to eql true

      expect(priv.valid?).to eql true
      expect(priv.valid?(rng)).to eql true
    end

    it 'returns valid fields' do
      expect(pub.get_field('n')).to be >= 1
      expect(pub.get_field('e')).to eql 65537

      expect(priv.get_field('p')).to be >= 1
      expect(priv.get_field('q')).to be >= 1
      expect(priv.get_field('d')).to be >= 1
      expect(priv.get_field('c')).to be >= 1
      expect(priv.get_field('d1')).to be >= 1
      expect(priv.get_field('d2')).to be >= 1
    end

    it 'raises an error when requesting invalid fields' do
      expect {
        pub.get_field('z')
      }.to raise_error Botan::Error

      expect {
        priv.get_field('z')
      }.to raise_error Botan::Error
    end

    it 'has a valid fingerprint length' do
      expect(pub.fingerprint('SHA-256').length).to eql 32
    end

    it 'has a valid estimated strength' do
      expect(pub.estimated_strength).to be >= 1
    end

    it 'has the correct algorithm name' do
      expect(pub.algo).to eql 'RSA'
    end

    it 'can export the public key' do
      expect(pub.export_pem.length).to be >= 1
      expect(pub.export_der.length).to be >= 1
      expect(pub.to_s.length).to be >= 1
    end

    it 'can export the private key' do
      expect(priv.export_pem.length).to be >= 1
      expect(priv.export_der.length).to be >= 1
    end

    it 'can export the private key (encrypted PEM)' do
      exported_pem = priv.export_encrypted_pem(password: 'test')
      expect(exported_pem.length).to be >= 1

      export = priv.export_encrypted_pem_timed(password: 'test',
                                               milliseconds: 5)
      expect(export[:data].length).to be >= 1
      expect(export[:iterations]).to be >= 1
    end

    it 'can export the private key (encrypted DER)' do
      exported_pem = priv.export_encrypted_der(password: 'test')
      expect(exported_pem.length).to be >= 1

      export = priv.export_encrypted_der_timed(password: 'test',
                                               milliseconds: 5)
      expect(export[:data].length).to be >= 1
      expect(export[:iterations]).to be >= 1
    end

    it 'can encrypt and decrypt (shortcut)' do
      ctext = pub.encrypt(symkey, rng: rng)
      decrypted = priv.decrypt(ctext)
      expect(decrypted).to eql symkey
    end

    it 'can sign and verify (shortcut)' do
      signature = priv.sign('message', rng: rng)
      expect(pub.verify(data: 'message', signature: signature)).to eql true
      expect(pub.verify(data: 'mess', signature: signature)).to eql false
    end
  end

  context 'ecdsa generation' do
    let(:priv) { Botan::PK::PrivateKey.generate('ECDSA', params: 'secp384r1', rng: Botan::RNG.new) }
    let(:pub) { priv.public_key }
    let(:sign) { Botan::PK::Sign.new(private_key: priv, padding: 'EMSA1(SHA-384)') }
    let(:verify) { Botan::PK::Verify.new(public_key: pub, padding: 'EMSA1(SHA-384)') }
    let(:rng) { Botan::RNG.new }
    let(:symkey) { rng.get(32) }

    it 'passes basic checks' do
      expect(pub.valid?).to eql true
      expect(pub.valid?(rng)).to eql true

      expect(priv.valid?).to eql true
      expect(priv.valid?(rng)).to eql true
    end

    it 'returns valid fields' do
      expect(pub.get_field('public_x')).to be >= 1
      expect(pub.get_field('public_y')).to be >= 1
      expect(pub.get_field('base_x')).to be >= 1
      expect(pub.get_field('base_y')).to be >= 1
      expect(pub.get_field('p')).to be >= 1
      expect(pub.get_field('a')).to be >= 1
      expect(pub.get_field('b')).to be >= 1
      expect(pub.get_field('cofactor')).to be >= 1
      expect(pub.get_field('order')).to be >= 1

      expect(priv.get_field('x')).to be >= 1
    end

    it 'raises an error when requesting invalid fields' do
      expect {
        pub.get_field('z')
      }.to raise_error Botan::Error

      expect {
        priv.get_field('z')
      }.to raise_error Botan::Error
    end

    it 'has a valid fingerprint length' do
      expect(pub.fingerprint('SHA-256').length).to eql 32
    end

    it 'has a valid estimated strength' do
      expect(pub.estimated_strength).to be >= 1
    end

    it 'has the correct algorithm name' do
      expect(pub.algo).to eql 'ECDSA'
    end

    it 'can export the public key' do
      expect(pub.export_pem.length).to be >= 1
      expect(pub.export_der.length).to be >= 1
    end

    it 'can export the private key' do
      expect(priv.export_pem.length).to be >= 1
      expect(priv.export_der.length).to be >= 1
    end

    it 'can sign and verify' do
      sign << 'mess'
      sign << 'age'
      signature = sign.finish(rng)

      verify << 'mes'
      verify << 'sage'
      expect(verify.check_signature(signature)).to eql true

      verify << 'mess of things'
      verify << 'age'
      expect(verify.check_signature(signature)).to eql false

      verify << 'message'
      expect(verify.check_signature(signature)).to eql true
    end

    it 'can sign and verify (shortcut)' do
      signature = priv.sign('message', rng: rng)
      expect(pub.verify(data: 'message', signature: signature)).to eql true
      expect(pub.verify(data: 'mess', signature: signature)).to eql false
    end
  end

  context 'ecdh generation' do
    let(:a_rng) { Botan::RNG.new('user') }
    let(:b_rng) { Botan::RNG.new('user') }
    let(:dh_kdf) { 'KDF2(SHA-384)' }
    let(:group) { 'secp256r1' }
    let(:a_dh_priv) { Botan::PK::PrivateKey.generate('ECDH', params: group, rng: Botan::RNG.new) }
    let(:b_dh_priv) { Botan::PK::PrivateKey.generate('ECDH', params: group, rng: Botan::RNG.new) }
    let(:a_dh) { Botan::PK::KeyAgreement.new(key: a_dh_priv, kdf: dh_kdf) }
    let(:b_dh) { Botan::PK::KeyAgreement.new(key: b_dh_priv, kdf: dh_kdf) }
    let(:a_dh_pub) { a_dh.public_value }
    let(:b_dh_pub) { b_dh.public_value }
    let(:a_salt) { a_rng.get(8) }
    let(:b_salt) { b_rng.get(8) }

    it 'key agreement' do
      a_key = a_dh.agree(other_key: b_dh_pub,
                         key_length: 32,
                         salt: a_salt + b_salt)
      b_key = b_dh.agree(other_key: a_dh_pub,
                         key_length: 32,
                         salt: a_salt + b_salt)
      expect(a_key).to eql b_key
    end
  end

  context Botan::PK::PrivateKey.method(:generate) do
    it 'errors on invalid algorithm' do
      expect {
        Botan::PK::PrivateKey.generate('fake')
      }.to raise_error Botan::Error
    end
  end
end


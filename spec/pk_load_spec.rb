# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'spec_helper'

describe 'PK loading' do
  context Botan::PK::PrivateKey.method(:from_data) do
    let(:private_key_pem) { File.read('spec/data/private_key.pem') }
    let(:key) { Botan::PK::PrivateKey.from_data(private_key_pem, password: '') }

    it 'responds to inspect' do
      expect(key.class.instance_methods(false).include?(:inspect)).to be true
      expect(key.inspect.class).to eql String
      expect(key.inspect.length).to be >= 1
    end

    it 'exports correctly' do
      expect(key.export_pem).to eql private_key_pem
    end

    it 'can be exported (encrypted) and loaded again' do
      exported = key.export_encrypted_pem(password: 'right')

      expect do
        Botan::PK::PrivateKey.from_data(exported, password: 'wrong')
      end.to raise_error Botan::Error

      reloaded = Botan::PK::PrivateKey.from_data(exported, password: 'right')
      expect(reloaded.export_pem.length).to be >= 1
    end
  end

  context Botan::PK::PublicKey.method(:from_data) do
    let(:public_key_pem) { File.read('spec/data/public_key.pem') }
    let(:key) { Botan::PK::PublicKey.from_data(public_key_pem) }

    it 'responds to inspect' do
      expect(key.class.instance_methods(false).include?(:inspect)).to be true
      expect(key.inspect.class).to eql String
      expect(key.inspect.length).to be >= 1
    end

    it 'exports correctly' do
      expect(key.export_pem).to eql public_key_pem
    end
  end
end


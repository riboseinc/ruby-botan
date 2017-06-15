# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'spec_helper'

describe 'mceies' do
  let(:priv) do
    Botan::PK::PrivateKey.generate('McEliece',
                                   params: '2960,57',
                                   rng: Botan::RNG.new)
  end
  let(:pub) { priv.public_key }
  let(:plaintext) { 'mce plaintext' }
  let(:ad) { 'mce AD' }
  let(:aead) { 'ChaCha20Poly1305' }
  let(:ciphertext) do
    Botan::PK.mceies_encrypt(public_key: pub,
                             aead: aead,
                             plaintext: plaintext,
                             ad: ad)
  end
  let(:decrypted) do
    Botan::PK.mceies_decrypt(private_key: priv,
                             aead: aead,
                             ciphertext: ciphertext,
                             ad: ad)
  end

  it 'encrypts and decrypts to the same value' do
    expect(decrypted).to eql plaintext
  end
end


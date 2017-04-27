require 'spec_helper'

describe 'mceies' do
  let(:priv) { Botan::PK::PrivateKey.generate('mce', [2960, 57], Botan::RNG.new) }
  let(:pub) { priv.public_key }
  let(:plaintext) { 'mce plaintext' }
  let(:ad) { 'mce AD' }
  let(:aead) { 'ChaCha20Poly1305' }
  let(:ciphertext) {
    Botan.mceies_encrypt(public_key: pub,
                         aead: aead,
                         plaintext: plaintext,
                         ad: ad)
  }
  let(:decrypted) {
    Botan.mceies_decrypt(private_key: priv,
                         aead: aead,
                         ciphertext: ciphertext,
                         ad: ad)
  }

  it 'encrypts and decrypts to the same value' do
    expect(decrypted).to eql plaintext
  end
end


require 'spec_helper'

describe Botan.method(:bcrypt_hash) do
  let(:phash) { Botan.bcrypt_hash('password') }

  it 'creates hashes with the expected length' do
    expect(phash.bytesize).to eql 60
  end
end

describe Botan.method(:bcrypt_valid?) do
  let(:password) { 'password' }
  let(:phash) { Botan.bcrypt_hash(password, work_factor: 5, rng: Botan::RNG.new) }

  it 'accepts correct passwords' do
    expect(
      Botan.bcrypt_valid?(password: password,
                          phash: phash)
    ).to eql true
  end

  it 'rejects incorrect passwords' do
    expect(
      Botan.bcrypt_valid?(password: '',
                          phash: phash)
    ).to eql false
    expect(
      Botan.bcrypt_valid?(password: 'wrong',
                          phash: phash)
    ).to eql false
  end
end


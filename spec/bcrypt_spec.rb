# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'spec_helper'

describe Botan::BCrypt.method(:hash) do
  let(:phash) { Botan::BCrypt.hash('password') }

  it 'creates hashes with the expected length' do
    expect(phash.bytesize).to be 60
  end
end

describe Botan::BCrypt.method(:valid?) do
  let(:password) { 'password' }
  let(:phash) { Botan::BCrypt.hash(password, work_factor: 5, rng: Botan::RNG.new) }

  it 'accepts correct passwords' do
    expect(
      Botan::BCrypt.valid?(password: password,
                           phash: phash)
    ).to be true
  end

  it 'rejects incorrect passwords' do
    expect(
      Botan::BCrypt.valid?(password: '',
                           phash: phash)
    ).to be false
    expect(
      Botan::BCrypt.valid?(password: 'wrong',
                           phash: phash)
    ).to be false
  end
end


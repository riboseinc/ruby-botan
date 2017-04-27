require 'spec_helper'

describe Botan.method(:kdf) do
  it 'produces the expected output' do
    expect(
      Botan.kdf(algo: 'KDF2(SHA-1)',
                secret: Botan.hex_decode('701F3480DFE95F57941F804B1B2413EF'),
                key_len: 7,
                salt: Botan.hex_decode('55A4E9DD5F4CA2EF82'),
                label: '')
    ).to eql Botan.hex_decode('fbecb3ccfeec6e')
  end
end

describe Botan.method(:pbkdf) do
  let(:result) {
      Botan.pbkdf(algo: 'PBKDF2(SHA-1)',
                  password: '',
                  key_len: 32,
                  iterations: 10000,
                  salt: Botan.hex_decode('0001020304050607'))
  }
  let(:salt) { result[:salt] }
  let(:iterations) { result[:iterations] }
  let(:key) { result[:key] }

  it 'returns the expected salt' do
    expect(salt).to eql "\x00\x01\x02\x03\x04\x05\x06\x07"
  end

  it 'returns the expected iterations' do
    expect(iterations).to eql 10000
  end

  it 'produces the expected output' do
    expect(key).to eql Botan.hex_decode('59B2B1143B4CB1059EC58D9722FB1C72471E0D85C6F7543BA5228526375B0127')
  end
end

describe Botan.method(:pbkdf_timed) do
  let(:result) {
      Botan.pbkdf_timed(algo: 'PBKDF2(SHA-256)',
                        password: 'xyz',
                        key_len: 32,
                        ms_to_run: 200)
  }
  let(:salt) { result[:salt] }
  let(:iterations) { result[:iterations] }
  let(:key) { result[:key] }

  it 'returns a salt of the expected size' do
    expect(salt.bytesize).to eql Botan::DEFAULT_KDF_SALT_LENGTH
  end

  it 'uses a valid number of iterations' do
    expect(iterations).to be >= 1
  end

  it 'produces an output of the correct size' do
    expect(key.bytesize).to eql 32
  end

  it 'produces the same output with the same inputs (timed and non-timed)' do
    expect(
      Botan.pbkdf(algo: 'PBKDF2(SHA-256)',
                  password: 'xyz',
                  key_len: 32,
                  iterations: iterations,
                  salt: salt)[:key]
    ).to eql key
  end
end


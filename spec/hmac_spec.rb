require 'spec_helper'

describe Botan::MAC do
  let(:hmac) { Botan::MAC.new('HMAC(SHA-256)') }
  let(:key) { Botan.hex_decode('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20') }
  let(:expected) { Botan.hex_decode('A21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181') }

  it 'has the correct output length' do
    expect(hmac.output_length).to eql 32
  end

  it 'produces the expected hash' do
    hmac.key = key
    hmac.update(Botan.hex_decode('616263'))
    expect(hmac.final).to eql expected
  end

  it 'can be incrementally updated' do
    hmac.key = key
    hmac.update(Botan.hex_decode('6162'))
    hmac << "\x63"
    expect(hmac.final).to eql expected
  end

  it 'can be cleared and reused' do
    hmac.key = key
    hmac.update(Botan.hex_decode('616263'))
    expect(hmac.final).to eql expected

    hmac.clear
    hmac.key = key
    hmac.update(Botan.hex_decode('616263'))
    expect(hmac.final).to eql expected
  end
end


require 'spec_helper'

describe Botan::MAC do
  let(:hmac) { Botan::MAC.new('HMAC(SHA-256)') }

  it 'has the correct output length' do
    expect(hmac.output_length).to eql 32
  end

  it 'produces the expected hash' do
    hmac.set_key(Botan.hex_decode('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20'))
    hmac.update(Botan.hex_decode('616263'))
    expect(hmac.final).to eql Botan.hex_decode('A21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181')
  end

  it 'can be incrementally updated' do
    hmac.set_key(Botan.hex_decode('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20'))
    hmac.update(Botan.hex_decode('6162'))
    hmac << "\x63"
    expect(hmac.final).to eql Botan.hex_decode('A21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181')
  end

  it 'can be cleared and reused' do
    hmac.set_key(Botan.hex_decode('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20'))
    hmac.update(Botan.hex_decode('616263'))
    expect(hmac.final).to eql Botan.hex_decode('A21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181')

    hmac.clear
    hmac.set_key(Botan.hex_decode('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20'))
    hmac.update(Botan.hex_decode('616263'))
    expect(hmac.final).to eql Botan.hex_decode('A21B1F5D4CF4F73A4DD939750F7A066A7F98CC131CB16A6692759021CFAB8181')
  end
end


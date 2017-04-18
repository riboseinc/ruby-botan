require 'spec_helper'

describe 'hex_encode and hex_decode' do
  let(:hex) { 'aabbccddeeff' }
  let(:bytes) { "\xAA\xBB\xCC\xDD\xEE\xFF".force_encoding('ascii-8bit') }

  it 'encodes and decodes correctly' do

    expect(
      Botan.hex_encode(bytes)
    ).to eql hex

    expect(
      Botan.hex_decode(hex)
    ).to eql bytes

    expect(
      Botan.hex_encode(Botan.hex_decode(hex))
    ).to eql hex
  end
end


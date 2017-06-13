# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

require 'spec_helper'

describe 'hex_encode and hex_decode' do
  let(:hex) { 'aabbccddeeff' }
  let(:data) { "\xAA\xBB\xCC\xDD\xEE\xFF".force_encoding(Encoding::BINARY) }

  it 'encodes and decodes correctly' do

    expect(
      Botan.hex_encode(data)
    ).to eql hex

    expect(
      Botan.hex_decode(hex)
    ).to eql data

    expect(
      Botan.hex_encode(Botan.hex_decode(hex))
    ).to eql hex
  end
end


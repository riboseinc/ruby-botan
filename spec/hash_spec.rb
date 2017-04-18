require 'spec_helper'

describe Botan::Hash do
  context 'MD5' do
    let(:md5) { Botan::Hash.new('MD5') }

    it 'produces the correct hash' do
      md5.update('test')
      expect(md5.final).to eql Botan.hex_decode('098F6BCD4621D373CADE4E832627B4F6')
    end
  end

  context 'SM3' do
    let(:sm3) { Botan::Hash.new('SM3') }

    it 'produces the correct hash' do
      sm3 << 'a'
      sm3 << 'bc'
      expect(sm3.final).to eql Botan.hex_decode('66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0')
    end

    it 'can be cleared and reused' do
      sm3 << 'abc'
      expect(sm3.final).to eql Botan.hex_decode('66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0')

      sm3.clear
      sm3 << ('abcd' * 16)
      expect(sm3.final).to eql Botan.hex_decode('DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293dCbA39C0C5732')
    end
  end
end


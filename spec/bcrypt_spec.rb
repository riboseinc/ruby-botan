require 'spec_helper'

describe Botan.method(:bcrypt) do
  let(:phash) { Botan.bcrypt('password', Botan::RNG.new) }

  it 'creates hashes with the expected length' do
    expect(phash.bytesize).to eql 60
  end
end

describe Botan.method(:check_bcrypt) do
  let(:password) { 'password' }
  let(:phash) { Botan.bcrypt(password, Botan::RNG.new) }

  it 'accepts correct passwords' do
    expect(Botan.check_bcrypt(password, phash)).to eql true
  end

  it 'rejects incorrect passwords' do
    expect(Botan.check_bcrypt('', phash)).to eql false
    expect(Botan.check_bcrypt('wrong', phash)).to eql false
  end
end


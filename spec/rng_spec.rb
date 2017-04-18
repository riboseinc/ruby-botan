require 'spec_helper'

describe Botan::RNG do
  let(:rng) { Botan::RNG.new('user') }

  it 'can reseed' do
    rng.reseed
  end

  it 'produces an output of the requested size' do
    expect(rng.get(50).bytesize).to eql 50
  end
end


require 'spec_helper'

describe Botan::RNG do
  let(:rng) { Botan::RNG.new('user') }

  it 'responds to inspect' do
    expect(rng.class.instance_methods(false).include?(:inspect)).to be true
    expect(rng.inspect.class).to eql String
    expect(rng.inspect.length).to be >= 1
  end

  it 'can reseed' do
    rng.reseed
  end

  it 'produces an output of the requested size' do
    expect(rng.get(50).bytesize).to eql 50
  end
end


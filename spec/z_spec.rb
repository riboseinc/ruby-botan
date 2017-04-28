require 'spec_helper'

describe 'GC' do
  it { GC.start; sleep 0.1; }
end


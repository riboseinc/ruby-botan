# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

require 'spec_helper'

describe 'GC' do
  it { GC.start; sleep 0.1; }
end


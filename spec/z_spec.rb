# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'spec_helper'

describe 'GC' do
  it do
    GC.start
    sleep 0.1
  end
end


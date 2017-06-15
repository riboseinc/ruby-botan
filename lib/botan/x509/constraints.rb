# frozen_string_literal: true

# (c) 2017 Ribose Inc.

module Botan
  module X509
    module Constraints
      DECIPHER_ONLY      = 1 << 7
      ENCIPHER_ONLY      = 1 << 8
      CRL_SIGN           = 1 << 9
      KEY_CERT_SIGN      = 1 << 10
      KEY_AGREEMENT      = 1 << 11
      DATA_ENCIPHERMENT  = 1 << 12
      KEY_ENCIPHERMENT   = 1 << 13
      NON_REPUDIATION    = 1 << 14
      DIGITAL_SIGNATURE  = 1 << 15
    end
  end # module
end # module


module Botan
  module X509
    module Constraints
      DIGITAL_SIGNATURE  = 32768
      NON_REPUDIATION    = 16384
      KEY_ENCIPHERMENT   = 8192
      DATA_ENCIPHERMENT  = 4096
      KEY_AGREEMENT      = 2048
      KEY_CERT_SIGN      = 1024
      CRL_SIGN           = 512
      ENCIPHER_ONLY      = 256
      DECIPHER_ONLY      = 128
    end
  end # module
end # module


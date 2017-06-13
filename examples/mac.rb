# -*- encoding: utf-8 -*-
# (c) 2017 Ribose Inc.
#

require 'botan'

hmac = Botan::MAC.new('HMAC(SHA-256)')
hmac.key = Botan.hex_decode('0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20')
hmac << "\x61\x62\x63"
puts hmac.hexdigest


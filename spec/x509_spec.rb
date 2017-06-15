# frozen_string_literal: true

# (c) 2017 Ribose Inc.

require 'spec_helper'
require 'base64'

describe Botan::X509::Certificate do
  context Botan::X509::Certificate.method(:from_data) do
    let(:cert) { Botan::X509::Certificate.from_data(File.read('spec/data/CSCA.CSCA.csca-germany.1.crt')) }

    it 'responds to inspect' do
      expect(cert.class.instance_methods(false).include?(:inspect)).to be true
      expect(cert.inspect.class).to eql String
      expect(cert.inspect.length).to be >= 1
    end

    it 'has the correct fingerprint' do
      expect(
        cert.fingerprint('SHA-1')
      ).to eql '32:42:1C:C3:EC:54:D7:E9:43:EC:51:F0:19:23:BD:85:1D:F2:1B:B9'
    end

    it 'has the correct times' do
      expect(cert.time_starts).to eql DateTime.parse('2007-07-19T15:27:18+00:00')
      expect(cert.time_expires).to eql DateTime.parse('2028-01-19T15:18:00+00:00')
    end

    it 'has the correct serial number' do
      expect(cert.serial_number).to eql "\x01"
    end

    it 'has the correct key ids' do
      expect(cert.authority_key_id).to eql Botan.hex_decode('0096452de588f966c4ccdf161dd1f3f5341b71e7')
      expect(cert.subject_key_id).to eql Botan.hex_decode('0096452de588f966c4ccdf161dd1f3f5341b71e7')
    end

    it 'has the correct subject public key bits' do
      expect(
        Base64.encode64(cert.subject_public_key_bits).chomp
      ).to eql 'MIHUBgcqhkjOPQIBMIHIAgEBMCgGByqGSM49AQECHQDXwTSqJkNmhioYMCV1
0deHsJ8HV5faifV+yMD/MDwEHGil5iypzmwcKZgDpsFTC1FOGCrYsAQqWcrS
n0MEHCWA9jzP5EE4hwcTsakjaeM+ITXSZtuzcjhsQAsEOQQNkCmtLH5c9DQI
I7KofcaMnkzjF0webv3uEsB9WKpW93LAcm8kxrieTs2sJDVLnpnKo/bTdhQC
zQIdANfBNKomQ2aGKhgwJXXQ+5jRFrxLbd68o6Wnk58CAQEDOgAEATZKSw8B
AulQKrncaFXZCwZab15eSDlfgwnVfBGrr/IXVmB+9nV+yYhsoiLYPKBLGpn6
Q8WpvOE='
    end

    it 'has the expected algorithm' do
      expect(cert.subject_public_key.algo).to eql 'ECDSA'
    end

    it 'has correct subject fields' do
      expect(cert.subject_info('Country')).to eql 'DE'
      expect(cert.subject_info('Organization')).to eql 'bund'
      expect(cert.subject_info('Organizational Unit')).to eql 'bsi'
      expect(cert.subject_info('SerialNumber')).to eql '4567'
      expect(cert.subject_info('Name')).to eql 'csca-germany'
      expect(cert.subject_info('Email')).to eql 'csca-germany@bsi.bund.de'
    end

    it 'has correct issuer fields' do
      expect(cert.issuer_info('Country')).to eql 'DE'
      expect(cert.issuer_info('Organization')).to eql 'bund'
      expect(cert.issuer_info('Organizational Unit')).to eql 'bsi'
      expect(cert.issuer_info('SerialNumber')).to eql '4567'
      expect(cert.issuer_info('Name')).to eql 'csca-germany'
    end

    it 'returns a string representation' do
      expect(cert.to_s.class).to eql String
    end

    it 'has correct allowed usages' do
      expect(cert.allowed_usage?(Botan::X509::Constraints::DIGITAL_SIGNATURE)).to be false
      expect(cert.allowed_usage?(Botan::X509::Constraints::NON_REPUDIATION)).to be false
      expect(cert.allowed_usage?(Botan::X509::Constraints::KEY_ENCIPHERMENT)).to be false
      expect(cert.allowed_usage?(Botan::X509::Constraints::DATA_ENCIPHERMENT)).to be false
      expect(cert.allowed_usage?(Botan::X509::Constraints::KEY_AGREEMENT)).to be false
      expect(cert.allowed_usage?(Botan::X509::Constraints::KEY_CERT_SIGN)).to be true
      expect(cert.allowed_usage?(Botan::X509::Constraints::CRL_SIGN)).to be true
      expect(cert.allowed_usage?(Botan::X509::Constraints::ENCIPHER_ONLY)).to be false
      expect(cert.allowed_usage?(Botan::X509::Constraints::DECIPHER_ONLY)).to be false
    end
  end

  context Botan::X509::Certificate.method(:from_file) do
    let(:cert) { Botan::X509::Certificate.from_file('spec/data/CSCA.CSCA.csca-germany.1.crt') }

    it 'has the correct fingerprint' do
      expect(
        cert.fingerprint('SHA-1')
      ).to eql '32:42:1C:C3:EC:54:D7:E9:43:EC:51:F0:19:23:BD:85:1D:F2:1B:B9'
    end

    it 'has the correct times' do
      expect(cert.time_starts).to eql DateTime.parse('2007-07-19T15:27:18+00:00')
      expect(cert.time_expires).to eql DateTime.parse('2028-01-19T15:18:00+00:00')
    end

    it 'has the correct serial number' do
      expect(cert.serial_number).to eql "\x01"
    end

    it 'has the correct key ids' do
      expect(cert.authority_key_id).to eql Botan.hex_decode('0096452de588f966c4ccdf161dd1f3f5341b71e7')
      expect(cert.subject_key_id).to eql Botan.hex_decode('0096452de588f966c4ccdf161dd1f3f5341b71e7')
    end

    it 'has the correct subject public key bits' do
      expect(
        Base64.encode64(cert.subject_public_key_bits).chomp
      ).to eql 'MIHUBgcqhkjOPQIBMIHIAgEBMCgGByqGSM49AQECHQDXwTSqJkNmhioYMCV1
0deHsJ8HV5faifV+yMD/MDwEHGil5iypzmwcKZgDpsFTC1FOGCrYsAQqWcrS
n0MEHCWA9jzP5EE4hwcTsakjaeM+ITXSZtuzcjhsQAsEOQQNkCmtLH5c9DQI
I7KofcaMnkzjF0webv3uEsB9WKpW93LAcm8kxrieTs2sJDVLnpnKo/bTdhQC
zQIdANfBNKomQ2aGKhgwJXXQ+5jRFrxLbd68o6Wnk58CAQEDOgAEATZKSw8B
AulQKrncaFXZCwZab15eSDlfgwnVfBGrr/IXVmB+9nV+yYhsoiLYPKBLGpn6
Q8WpvOE='
    end

    it 'has the expected algorithm' do
      expect(cert.subject_public_key.algo).to eql 'ECDSA'
    end

    it 'has correct subject fields' do
      expect(cert.subject_info('Country')).to eql 'DE'
      expect(cert.subject_info('Organization')).to eql 'bund'
      expect(cert.subject_info('Organizational Unit')).to eql 'bsi'
      expect(cert.subject_info('SerialNumber')).to eql '4567'
      expect(cert.subject_info('Name')).to eql 'csca-germany'
      expect(cert.subject_info('Email')).to eql 'csca-germany@bsi.bund.de'
    end

    it 'has correct issuer fields' do
      expect(cert.issuer_info('Country')).to eql 'DE'
      expect(cert.issuer_info('Organization')).to eql 'bund'
      expect(cert.issuer_info('Organizational Unit')).to eql 'bsi'
      expect(cert.issuer_info('SerialNumber')).to eql '4567'
      expect(cert.issuer_info('Name')).to eql 'csca-germany'
    end

    it 'returns a string representation' do
      expect(cert.to_s.class).to eql String
    end
  end # context
end # describe


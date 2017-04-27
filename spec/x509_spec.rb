require 'spec_helper'
require 'base64'

describe Botan::X509Cert do
  context Botan::X509Cert.method(:from_data) do
    let(:cert) { Botan::X509Cert.from_data(File.read('spec/data/CSCA.CSCA.csca-germany.1.crt')) }

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
      expect(cert.subject_public_key.algo_name).to eql 'ECDSA'
    end

    it 'has correct subject fields' do
      expect(cert.subject_info('Name', 0)).to eql 'csca-germany'
      expect(cert.subject_info('Email', 0)).to eql 'csca-germany@bsi.bund.de'
      expect(cert.subject_info('Organization', 0)).to eql 'bund'
      expect(cert.subject_info('Organizational Unit', 0)).to eql 'bsi'
      expect(cert.subject_info('Country', 0)).to eql 'DE'
    end
  end

  context Botan::X509Cert.method(:from_file) do
    let(:cert) { Botan::X509Cert.from_file('spec/data/CSCA.CSCA.csca-germany.1.crt') }

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
      expect(cert.subject_public_key.algo_name).to eql 'ECDSA'
    end

    it 'has correct subject fields' do
      expect(cert.subject_info('Name', 0)).to eql 'csca-germany'
      expect(cert.subject_info('Email', 0)).to eql 'csca-germany@bsi.bund.de'
      expect(cert.subject_info('Organization', 0)).to eql 'bund'
      expect(cert.subject_info('Organizational Unit', 0)).to eql 'bsi'
      expect(cert.subject_info('Country', 0)).to eql 'DE'
    end

    it 'returns a string representation' do
      expect(cert.to_s.class).to eql String
    end
  end # context
end # describe


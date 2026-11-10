# frozen_string_literal: true

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'botan/version'

Gem::Specification.new do |spec|
  spec.name          = 'botan'
  spec.version       = Botan::VERSION
  spec.authors       = ['Ribose Inc.']
  spec.email         = ['packaging@ribose.com']

  spec.summary       = 'The Ruby interface for Botan.'
  spec.homepage      = 'https://www.ribose.com'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").grep(%r{^(lib)/})
  spec.extra_rdoc_files = %w[README.md LICENSE.txt]
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 3.1'

  spec.metadata['yard.run'] = 'yard'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'simplecov'
  spec.add_development_dependency 'yard'
  spec.add_development_dependency 'rubocop'

  spec.add_runtime_dependency 'ffi', '~> 1.9'
end


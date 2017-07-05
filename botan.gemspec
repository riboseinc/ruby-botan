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

  spec.required_ruby_version = '>= 2.3.0'

  spec.has_rdoc = 'yard'
  spec.metadata['yard.run'] = 'yard'

  spec.add_development_dependency 'bundler', '~> 1.13'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'simplecov', '~> 0.14'
  spec.add_development_dependency 'codecov', '~> 0.1'
  spec.add_development_dependency 'yard', '~> 0.8.7'
  spec.add_development_dependency 'redcarpet', '~> 3.4'
  spec.add_development_dependency 'rubocop', '~> 0.49.1'

  spec.add_runtime_dependency 'ffi', '~> 1.9'
end


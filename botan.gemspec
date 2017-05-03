# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'botan/version'

Gem::Specification.new do |spec|
  spec.name          = "botan"
  spec.version       = Botan::VERSION
  spec.authors       = ["Ribose Inc."]
  spec.email         = ["packaging@ribose.com"]

  spec.summary       = "The Ruby interface for Botan."
  spec.homepage      = "https://www.ribose.com"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.13"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "simplecov"
  spec.add_development_dependency "codecov"

  spec.add_runtime_dependency 'ffi'
end

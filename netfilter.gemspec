# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'netfilter/version'

Gem::Specification.new do |gem|
  gem.name          = "netfilter"
  gem.version       = Netfilter::VERSION
  gem.authors       = ["Corin Langosch"]
  gem.email         = ["info@corinlangosch.com"]
  gem.description   = %q{Awesome Netfilter Management Gem}
  gem.summary       = %q{Awesome Netfilter Management Gem}
  gem.homepage      = ""

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_dependency "activesupport", ">= 3.0.0"

  gem.add_development_dependency "rspec", "~> 2.12"
  gem.add_development_dependency "awesome_print"
  gem.add_development_dependency "json"
end

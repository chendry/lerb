#!/usr/bin/env ruby

require 'uri'
require 'openssl'

class LERB
  def initialize(uri, key)
    @uri = URI(uri)
    @key = OpenSSL::PKey::RSA.new(File.read(key))
  end

  def run
    puts "hello, world"
  end
end

LERB.new("https://acme-staging.api.letsencrypt.org/directory", "./test-key").run

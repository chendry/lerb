#!/usr/bin/env ruby

require 'uri'
require 'openssl'
require 'open-uri'
require 'json'

class LERB
  def initialize(uri, key)
    @uri = URI(uri)
    @key = OpenSSL::PKey::RSA.new(File.read(key))
  end

  def run
    puts directory.inspect
  end

  private

    def directory
      @directory ||= JSON.parse(open(@uri.to_s).read)
    end
end

LERB.new("https://acme-staging.api.letsencrypt.org/directory", "./test-key").run

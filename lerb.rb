#!/usr/bin/env ruby

require 'uri'
require 'openssl'
require 'open-uri'
require 'json'
require 'base64'
require 'net/http'

class JWS
  def initialize(key, nonce, payload)
    @key = key
    @nonce = nonce
    @payload = payload
  end

  def build
    "#{signing_input}.#{signature}"
  end

  private

    def signing_input
      b64(header) + "." + b64(@payload)
    end

    def signature
      b64(@key.sign(OpenSSL::Digest::SHA256.new, signing_input))
    end

    def b64(bin)
      Base64.urlsafe_encode64(bin).gsub(/=+$/, "")
    end

    def header
      {
        alg: "RS256",
        nonce: @nonce,
        jwk: {
          kty: "RSA",
          n: b64(number_to_bytes(@key.params["n"])),
          e: b64(number_to_bytes(@key.params["e"]))
        }
      }.to_json
    end

    def number_to_bytes(n)
      n.to_s(16).scan(/../).collect(&:hex).pack("C*")
    end
end

class LERB
  def initialize(uri, key)
    @uri = URI(uri)
    @key = OpenSSL::PKey::RSA.new(File.read(key))
  end

  def run
    puts nonce
  end

  private

    def directory
      @directory ||= JSON.parse(open(@uri.to_s).read)
    end

    def nonce
      http = Net::HTTP.new(@uri.host, @uri.port)
      http.use_ssl = true

      http.start do |h|
        h.request(Net::HTTP::Head.new(@uri))["Replay-Nonce"]
      end
    end
end

LERB.new("https://acme-staging.api.letsencrypt.org/directory", "./test-key").run

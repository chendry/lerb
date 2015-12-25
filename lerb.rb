#!/usr/bin/env ruby

require 'uri'
require 'openssl'
require 'open-uri'
require 'json'
require 'base64'
require 'net/http'

module LERB

  class Client
    def initialize(uri, key)
      @uri = URI(uri)
      @key = OpenSSL::PKey::RSA.new(File.read(key))
    end

    def run
      JWKThumbprint.new(@key).build
    end

    def new_registration(email)
      execute directory["new-reg"],
        resource: "new-reg",
        contact: [ "mailto:#{email}" ]
    end

    def agree_to_tos!
      registration = execute(registration_uri, resource: "reg")

      execute registration_uri,
        resource: "reg",
        agreement: registration.links["terms-of-service"]
    end

    def new_authorization(domain)
      execute directory["new-authz"],
        resource: "new-authz",
        identifier: {
          type: "dns",
          value: domain
        }
    end

    private

      def directory
        @directory ||= JSON.parse(open(@uri.to_s).read)
      end

      def execute(uri, payload)
        uri = URI(uri)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true
        http.set_debug_output(STDOUT)

        request = Net::HTTP::Post.new(uri.request_uri)
        request.body = LERB::JWS.new(@key, nonce, payload.to_json).build

        LERB::Response.new(http.request(request))
      end

      def nonce
        http = Net::HTTP.new(@uri.host, @uri.port)
        http.use_ssl = true

        http.start do |h|
          h.request(Net::HTTP::Head.new(@uri))["Replay-Nonce"]
        end
      end

      def registration_uri
        @registration_uri ||= execute(directory["new-reg"], resource: "new-reg").location
      end
  end

  class Response
    def initialize(response)
      @response = response
    end

    def location
      @response["Location"]
    end

    def links
      if links = @response["Link"]
        Hash[links.scan(/\<(.+?)\>\;rel="(.+?)"/)].invert
      end
    end
  end

  class Helper
    def self.b64(bin)
      Base64.urlsafe_encode64(bin).gsub(/=+$/, "")
    end

    def self.number_to_bytes(n)
      n.to_s(16).scan(/../).collect(&:hex).pack("C*")
    end
  end

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
        Helper.b64(header) + "." + Helper.b64(@payload)
      end

      def signature
        Helper.b64(@key.sign(OpenSSL::Digest::SHA256.new, signing_input))
      end

      def header
        {
          alg: "RS256",
          nonce: @nonce,
          jwk: {
            kty: "RSA",
            n: Helper.b64(Helper.number_to_bytes(@key.params["n"])),
            e: Helper.b64(Helper.number_to_bytes(@key.params["e"]))
          }
        }.to_json
      end
  end

  class JWKThumbprint
    def initialize(key)
      @key = key
    end

    def build
      jwk = {
        e: Helper.b64(Helper.number_to_bytes(@key.params["n"])),
        kty: "RSA",
        n: Helper.b64(Helper.number_to_bytes(@key.params["n"]))
      }.to_json

      Helper.b64(OpenSSL::Digest::SHA256.digest(jwk))
    end
  end

end

LERB::Client.new("https://acme-staging.api.letsencrypt.org/directory", "./test-key").run

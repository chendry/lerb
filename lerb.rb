#!/usr/bin/env ruby

require 'uri'
require 'openssl'
require 'open-uri'
require 'json'
require 'base64'
require 'net/http'
require 'optparse'
require 'forwardable'

module LERB

  class CLI
    def self.run(args)
      klass = case args.shift
        when "new-reg" then LERB::Commands::NewReg
        when "new-authz" then LERB::Commands::NewAuthz
        when "challenge" then LERB::Commands::Challenge
        when "authz" then LERB::Commands::Authz
        when "new-cert" then LERB::Commands::NewCert
        when "cert" then LERB::Commands::Cert
        else LERB::Commands::Help
      end

      command = klass.new
      command.execute(args)
    end
  end

  class MyOptionParser
    extend Forwardable

    def initialize
      @required = [ ]
      @parser = OptionParser.new
      @options = { }
    end

    def show_help
      puts @parser
    end

    def_delegators :@parser, :banner=, :separator, :on

    def opt(short, long, *args)
      add_option(short, long, *args)
    end

    def req(short, long, *args)
      add_option(short, long, *args)
      @required << long
    end

    def parse(args)
      @parser.parse(args)

      if missing.any?
        puts "missing arguments: #{missing.join(", ")}"
        puts @parser
        exit 1
      end

      Hash[
        @options.map do |k, v|
          [ k.gsub(/^--/, '').gsub('-','_').gsub(/=.*/, '').to_sym, v ]
        end
      ]
    end

    private

      def add_option(short, long, *args)
        @parser.on short, long, *args do |v|
          @options[long] = v
        end
      end

      def missing
        @required - @options.keys
      end
  end

  module Commands
    class Base
      def execute(args)
        @options = MyOptionParser.new
        build_options(@options)
        run(@options.parse(args))
      end

      private

        def add_common_options(o)
          o.req "-k", "--account-key=PATH", "private RSA key used for authentication"
          o.opt "-j", "--json", "output JSON responses from server"
          o.opt "-s", "--script", "output script-friendly export commands"

          o.on "--version", "print version number" do
            puts "0.0.1"
            exit
          end

          o.on "--help", "display this message" do
            @options.show_help
            exit
          end
        end
    end

    class Help < Base
      def run(options)
      end

      private

        def build_options(o)
          o.banner = "usage: lerb.rb command [options]"
          o.separator "  commands: new-reg, new-authz, challenge, authz, new-cert, cert"
          add_common_options(o)
        end
    end

    class NewReg < Base
      def run(options)
        puts options.inspect
      end

      private

        def build_options(o)
          o.banner = "usage: lerb.rb new-req [options]"
          add_common_options(o)
          o.separator ""
          o.separator "new-req command options:"
          o.req "-e", "--email=EMAIL" , "email address to use for registration"
        end
    end

    class NewAuthz < Base
      def run(options)
        puts options.inspect
      end

      private

        def build_options(o)
          o.banner = "usage: lerb.rb new-authz [options]"
          add_common_options(o)
          o.separator ""
          o.separator "new-authz command options:"
          o.req "-d", "--domain=DOMAIN", "domain name for which to request authorization"
        end
    end

    class Challenge < Base
      def run(options)
        puts options.inspect
      end

      private

        def build_options(o)
          o.banner = "usage: lerb.rb challenge [options]"
          add_common_options(o)
          o.separator ""
          o.separator "challenge command options:"
          o.req "-t", "--type=TYPE", "type of challenge"
          o.req "-u", "--uri=URI", "challenge URI"
          o.req "-T", "--token=TOKEN", "challenge token"
        end
    end
  end

  class Client
    def initialize(uri, key)
      @uri = URI(uri)
      @account_key = AccountKey.new(OpenSSL::PKey::RSA.new(File.read(key)))
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

    def new_cert(csr)
      execute directory["new-cert"],
        resource: "new-cert",
        csr: Helper.b64(File.read(csr))
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
        request.body = LERB::JWS.new(@account_key, nonce, payload.to_json).build

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

  class AccountKey
    def initialize(key)
      @key = key
    end

    def jwk
      {
        e: Helper.b64(Helper.number_to_bytes(@key.params["e"])),
        kty: "RSA",
        n: Helper.b64(Helper.number_to_bytes(@key.params["n"]))
      }
    end

    def sign(input)
      @key.sign(OpenSSL::Digest::SHA256.new, input)
    end
  end

  class JWS
    def initialize(account_key, nonce, payload)
      @account_key = account_key
      @nonce = nonce
      @payload = payload
    end

    def build
      signing_input + "." + Helper.b64(@account_key.sign(signing_input))
    end

    private

      def signing_input
        Helper.b64(header) + "." + Helper.b64(@payload)
      end

      def header
        {
          alg: "RS256",
          nonce: @nonce,
          jwk: @account_key.jwk
        }.to_json
      end
  end

  class KeyAuthorization
    def initialize(account_key)
      @account_key = account_key
    end

    def build(token)
      token + "." + Helper.b64(jwk_thumbprint)
    end

    private

      def jwk_thumbprint
        OpenSSL::Digest::SHA256.digest(@account_key.jwk.to_json)
      end
  end

end

# LERB::Client.new("https://acme-staging.api.letsencrypt.org/directory", "./test-key").run
LERB::CLI.run(ARGV)

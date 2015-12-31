#!/usr/bin/env ruby

require 'uri'
require 'openssl'
require 'open-uri'
require 'json'
require 'base64'
require 'net/http'
require 'optparse'
require 'forwardable'

class String
  def unindent
    gsub(/^#{match(/^\s+/)}/, "").gsub("\n\n\n+", "\n\n").strip
  end
end


module LERB

  class CLI
    def self.run(args)
      command = case command_name = args.shift
        when "new-reg" then LERB::Commands::NewReg.new
        when "reg" then LERB::Commands::Reg.new
        when "new-authz" then LERB::Commands::NewAuthz.new
        when "challenge" then LERB::Commands::Challenge.new
        when "new-cert" then LERB::Commands::NewCert.new
        when "cert" then LERB::Commands::Cert.new
        when nil then  LERB::Commands::Help.new
        else LERB::Commands::Help.new("error: unknown command: #{command_name}")
      end

      command.run(args)
    end
  end

  class MyOptionParser
    extend Forwardable

    def initialize
      @parser = OptionParser.new
      @options = { }
      @required = [ ]
    end

    def_delegators :@parser, :banner=, :separator

    def usage
      @parser.to_s
    end

    def add_common_options
      separator ""
      separator "common options:"
      add_req "--account-key=PATH", "private RSA key used for authentication"
      add_opt "--json", "output JSON responses from server"
      add_opt "--script", "output script-friendly export commands"
      add_opt "--verbose", "verbose HTTP logging"

      @parser.on "--version", "print version number" do
        puts "0.0.1"
        exit
      end

      @parser.on "--help", "display this message" do
        puts usage
        exit
      end
    end

    def add_req(long, *args)
      @required << long
      add_opt(long, *args)
    end

    def add_opt(long, *args)
      @parser.on long, *args do |v|
        @options[long] = v
      end
    end

    def parse!(args)
      @parser.parse(args)

      check_for_missing_arguments!

      Hash[
        @options.map do |long, v|
          [ long_to_key(long), v ]
        end
      ]
    end

    private

      def check_for_missing_arguments!
        missing = @required - @options.keys
        if missing.any?
          puts "error: the following argument(s) are required: #{missing.join(", ")}"
          puts usage
          exit
        end
      end

      def long_to_key(long)
        long.gsub(/^--/, '').gsub('-', '_').gsub(/=.*/, '').to_sym
      end
  end

  module Commands
    class Help
      def initialize(error = nil)
        @error = error
      end

      def run(args)
        o = MyOptionParser.new
        o.banner = "usage: lerb.rb command [options]"
        o.separator "  commands: new-reg, reg, new-authz, challenge, new-cert, cert"
        o.add_common_options

        puts @error if @error
        puts o.usage
      end
    end

    class BaseCommand
      def run(args)
        options_hash = parse_arguments(args)
        uri = "https://acme-staging.api.letsencrypt.org/directory"
        client = LERB::Client.new(uri, options_hash[:account_key], options_hash[:verbose])
        response = run_with_options(client, options_hash)
        puts output(response, options_hash)
      end

      private

        def output(response, options_hash)
          output = self.class.const_get("Output").new(response, options_hash)

          case
            when options_hash[:json] then output.json
            when options_hash[:script] then output.script
            else output.human
          end
        end

        def parse_arguments(args)
          parser = MyOptionParser.new
          parser.banner = "usage: lerb.rb #{command_name} [options]"
          parser.add_common_options
          parser.separator ""
          parser.separator "#{command_name} command options"
          add_command_options(parser)
          parser.parse!(args)
        end

        def command_name
          self.class.name.split("::").last.split(/(?=[A-Z])/).join("-").downcase
        end
    end

    class BaseOutput
      def initialize(response, options)
        @response = response
        @options = options
      end

      def json
        output = {
          headers: @response.headers,
          links: @response.links,
          body: JSON.parse(@response.body)
        }

        output.to_json
      end

      def human
        json
      end

      def script
      end

      private

        def tos_instructions
          return unless uri = @response.links["terms-of-service"]

          <<-END.unindent
            You must first agree to the terms of service before requesting a certificate.
            Do so using the following command:

            ./lerb.rb reg \\
              --account-key=#{@options[:account_key]} \\
              --agreement=#{uri}
          END
        end
    end

    class NewReg < BaseCommand
      def add_command_options(p)
        p.add_opt "--email=EMAIL" , "email address to use for registration"
      end

      def run_with_options(client, options)
        hash = { }
        hash[:contact] = [ "mailto:#{options[:email]}" ] if options[:email]
        client.new_reg(hash)
      end

      class Output < BaseOutput
        def human
          case @response.code
            when "201"
              puts <<-END.unindent
                Your account has been created.  Make sure to keep your account key safe as it
                is required for authenticating subsequent operations.

                #{tos_instructions}
              END
            when "409"
              puts <<-END.unindent
                An account already exists for the supplied account key.  Use the following
                command to get details about the existing account:

                ./lerb.rb reg --account-key=#{@options[:account_key]}
              END
          end
        end

        def script
          puts <<-END.unindent
            export LERB_REGISTRATION_URI="#{@response.location}"
          END
        end
      end
    end

    class Reg < BaseCommand
      def add_command_options(p)
        p.add_opt "--agreement=URI", "agree to the terms of service"
      end

      def run_with_options(client, options)
        hash = { }
        hash[:agreement] = options[:agreement] if options[:agreement]
        client.reg(options[:uri], hash)
      end

      class Output < BaseOutput
        def human
          <<-END.unindent
            #{tos_instructions}
          END
        end
      end
    end

    class NewAuthz < BaseCommand
      def add_common_options(p)
        p.add_req "--domain=DOMAIN", "domain name for which to request authorization"
      end

      def run_with_options(client, options)
        puts options.inspect
      end

      class Output < BaseOutput
      end
    end

    class Challenge < BaseCommand
      def add_common_options(p)
        p.add_req "--type=TYPE", "type of challenge"
        p.add_req "--uri=URI", "challenge URI"
        p.add_req "--token=TOKEN", "challenge token"
      end

      def run_with_options(client, options)
      end

      class Output < BaseOutput
      end
    end

    class NewCert < BaseCommand
      def add_common_options(p)
      end

      def run_with_options(client, options)
      end

      class Output < BaseOutput
      end
    end

    class Cert < BaseCommand
      def add_common_options(p)
      end

      def run_with_options(client, options)
      end

      class Output < BaseOutput
      end
    end
  end

  class Client
    def initialize(uri, key, verbose)
      @uri = URI(uri)
      @account_key = AccountKey.new(OpenSSL::PKey::RSA.new(File.read(key)))
      @verbose = verbose
    end

    def new_reg(hash)
      execute directory["new-reg"], hash.merge(resource: "new-reg")
    end

    def reg(uri, hash)
      execute registration_uri, hash.merge(resource: "reg")
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
        http.set_debug_output(STDOUT) if @verbose

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

    def code
      @response.code
    end

    def location
      @response["Location"]
    end

    def body
      @response.body
    end

    def headers
      @response.to_hash
    end

    def links
      if links = @response["Link"]
        Hash[links.scan(/\<(.+?)\>\;rel="(.+?)"/)].invert
      else
        { }
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

LERB::CLI.run(ARGV)

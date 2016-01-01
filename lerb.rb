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

  def blank?
    strip.length == 0
  end
end

class NilClass
  def blank?
    true
  end
end

module LERB

  class CLI
    def self.run(args)
      klass = case command_name = args.shift
        when "new-reg" then LERB::Commands::NewReg
        when "reg" then LERB::Commands::Reg
        when "new-authz" then LERB::Commands::NewAuthz
        when "challenge" then LERB::Commands::Challenge
        when "new-cert" then LERB::Commands::NewCert
        when "cert" then LERB::Commands::Cert
        when nil then  LERB::Commands::Help
        else
          puts "error: unknown command: #{command_name}\n\n"
          LERB::Commands::Help
      end

      klass.new.run(args)
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
      @parser.to_s + "\n"
    end

    def add_common_options
      separator ""
      separator "common options:"
      add_opt "--account-key=PATH", "private RSA key used for authentication", "(defaults to ~/.lerb/account_key)"
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

    def generate_banner(command_name)
      @parser.banner = "usage: lerb.rb #{command_name} #{@required.join(" ")} [options]"
    end

    def parse!(args)
      @parser.parse(args)

      check_for_missing_arguments!

      Hash[
        @options.collect do |k, v|
          [ long_to_key(k), v ]
        end
      ]
    end

    private

      def check_for_missing_arguments!
        missing = (@required - @options.keys)
        if missing.any?
          puts "error: the following argument(s) are required: #{missing.join(" ")}\n\n"
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
      def run(args)
        o = MyOptionParser.new
        o.banner = "usage: lerb.rb command [options]"
        o.separator "  commands: new-reg, reg, new-authz, challenge, new-cert, cert"
        o.add_common_options
        puts o.usage
      end
    end

    class BaseCommand
      def run(args)
        options = parse_arguments(args)

        uri = "https://acme-staging.api.letsencrypt.org/directory"
        # uri = "https://acme-v01.api.letsencrypt.org/directory"

        client = LERB::Client.new(uri, LERB::AccountKey.new(options[:account_key]))
        client.set_verbose if options[:verbose]

        response = run_with_options(client, options)
        render_output(client, response, options)
      end

      private

        def parse_arguments(args)
          parser = MyOptionParser.new
          parser.add_common_options
          parser.separator ""
          parser.separator "#{command_name} command options:"
          add_command_options(parser)
          parser.generate_banner(command_name)
          parser.parse!(args)
        end

        def command_name
          self.class.name.split("::").last.split(/(?=[A-Z])/).join("-").downcase
        end

        def render_output(client, response, options)
          output = self.class.const_get("Output").new(client, response, options)

          puts case
            when options[:json] then output.json
            when options[:script] then output.script
            else output.human
          end

          puts ""
        end
    end

    class BaseOutput
      def initialize(client, response, options)
        @client = client
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
          return unless uri = pending_agreement_uri rescue nil

          <<-END.unindent
            You must first agree to the terms of service before requesting a certificate.
            Do so using the following command:

              ./lerb.rb reg --agreement=#{uri}
          END
        end
    end

    class NewReg < BaseCommand
      def add_command_options(p)
        p.add_req "--email=EMAIL" , "email address to use for registration"
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
              <<-END.unindent
                Your account has been created.  Make sure to keep your account key safe as it
                is required for authenticating subsequent operations.

                  #{tos_instructions}
              END
            when "409"
              <<-END.unindent
                An account already exists for the supplied account key.  Use the following
                command to get details about the existing account:

                  ./lerb.rb reg
              END
          end
        end

        def script
          <<-END.unindent
            export LERB_REGISTRATION_URI="#{@response.location}"
          END
        end

        private

          def pending_agreement_uri
            @response.links["terms-of-service"]
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

        private

          def pending_agreement_uri
            signed = JSON.parse(@response.body)["agreement"]
            current = @response.links["terms-of-service"]

            if current != signed
              current
            else
              nil
            end
          end
      end
    end

    class NewAuthz < BaseCommand
      def add_command_options(p)
        p.add_req "--domain=DOMAIN", "domain name for which to request authorization"
      end

      def run_with_options(client, options)
        client.new_authz(options[:domain])
      end

      class Output < BaseOutput
        def human
          <<-END.unindent
            The authorization has been created.  In order to prove control over this
            domain, you must perform one of the following challenges:

            #{challenges.join("\n\n")}
          END
        end

        private

          def challenges
            JSON.parse(@response.body)["challenges"].map do |challenge|
              case challenge["type"]
                when /^dns/ then dns_challenge(challenge)
                when /^http/ then http_challenge(challenge)
                when /^tls-sni/ then tls_sni_challenge(challenge)
              end
            end
          end

          def dns_challenge(challenge)
            <<-END.unindent
              DNS:
                - No description yet.
            END
          end

          def http_challenge(challenge)
            <<-END.unindent
              HTTP:
                Place a file on your web server such that a request to:
                  http://#{@options[:domain]}/.well-known/acme-challenge/#{challenge["token"]}

                returns the following data:
                  #{@client.key_authorization(challenge["token"])}

                Then respond to the challenge by issuing the following command:
                  ./lerb.rb challenge \\
                    --uri=#{challenge["uri"]} \\
                    --type=#{challenge["type"]} \\
                    --token=#{challenge["token"]}
            END
          end

          def tls_sni_challenge(challenge)
            <<-END.unindent
              TLS-SNI:
                - No description yet.
            END
          end
      end
    end

    class Challenge < BaseCommand
      def add_command_options(p)
        p.add_req "--uri=URI", "challenge URI"
        p.add_req "--type=TYPE", "type of challenge"
        p.add_req "--token=TOKEN", "challenge token"
      end

      def run_with_options(client, options)
        client.challenge(options[:uri], options[:type], options[:token])
      end

      class Output < BaseOutput
      end
    end

    class NewCert < BaseCommand
      def add_command_options(p)
        p.add_req "--csr=CSR", "CSR in either PEM or DER format"
      end

      def run_with_options(client, options)
        csr = OpenSSL::X509::Request.new(File.read(options[:csr]))
        client.new_cert(csr.to_der)
      end

      class Output < BaseOutput
        def human
          cert = OpenSSL::X509::Certificate.new(@response.body)
          cert.to_pem
        end
      end
    end

    class Cert < BaseCommand
      def add_command_options(p)
      end

      def run_with_options(client, options)
      end

      class Output < BaseOutput
      end
    end
  end

  class Client
    def initialize(uri, account_key)
      @uri = URI(uri)
      @http = Net::HTTP.new(@uri.host, @uri.port)
      @http.use_ssl = true
      @account_key = account_key
    end

    def set_verbose
      @http.set_debug_output(STDOUT)
    end

    def new_reg(hash)
      execute directory["new-reg"], hash.merge(resource: "new-reg")
    end

    def reg(uri, hash)
      execute registration_uri, hash.merge(resource: "reg")
    end

    def new_authz(domain)
      execute directory["new-authz"],
        resource: "new-authz",
        identifier: {
          type: "dns",
          value: domain
        }
    end

    def challenge(uri, type, token)
      execute uri,
        resource: "challenge",
        type: type,
        keyAuthorization: key_authorization(token)
    end

    def new_cert(csr)
      execute directory["new-cert"],
        resource: "new-cert",
        csr: Helper.b64(csr)
    end

    def key_authorization(token)
      KeyAuthorization.new(@account_key).build(token)
    end

    private

      def directory
        @directory ||= JSON.parse(open(@uri.to_s).read)
      end

      def execute(uri, payload)
        request = Net::HTTP::Post.new(uri)
        request.body = LERB::JWS.new(@account_key, nonce, payload.to_json).build
        LERB::Response.new(@http.request(request))
      end

      def nonce
        @http.request(Net::HTTP::Head.new(@uri))["Replay-Nonce"]
      end

      def registration_uri
        @registration_uri ||= begin
          response = execute(directory["new-reg"], resource: "new-reg")
          response.location
        end
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
    def initialize(path)
      @path = path || AccountKey.default_path
      load_key!
    end

    def self.default_path
      File.expand_path("~/.lerb/account_key")
    end

    def is_default_path?
      @path == AccountKey.default_path
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

    private

      def load_key!
        @key = OpenSSL::PKey::RSA.new(File.read(@path))
      rescue
        if user_aware_of_account_key?
          puts "error: unable to load RSA private key at #{@path}"
        else
          show_account_key_help
        end

        exit 1
      end

      def user_aware_of_account_key?
        File.exists?(@path) || !is_default_path?
      end

      def show_account_key_help
        puts <<-END.unindent
          error: could not load account key.

          Your account key is required as it is used for authentication.  You may either
          use the --account-key=PATH argument, or store the account key at
          ~/.lerb/account_key to be loaded by default.

          Use the following example commands to generate an account key:

            mkdir -p ~/.lerb && openssl genrsa -aes128 -out ~/.lerb/account_key 2048
        END
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

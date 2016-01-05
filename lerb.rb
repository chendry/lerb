#!/usr/bin/env ruby

require 'uri'
require 'openssl'
require 'open-uri'
require 'json'
require 'base64'
require 'net/http'
require 'optparse'
require 'shellwords'

class String
  def unindent
    gsub(/^#{match(/^\s+/)}/, "").gsub("\n\n\n+", "\n\n").strip
  end

  def strip_blank_account_key
    lines.reject do |line|
      line.match /^\s+--account-key=\s*(\/\/)?$/
    end.join
  end
end

module LERB

  class CLI
    def initialize(args)
      @command_name = args.shift
      @options = parse_args(args)
      @client = build_client
    end

    def run
      result = command_class.new.run(@client, @options)
      command_class::Output.new(@client, @options, result).run
    end

    private

      def command_class
        case @command_name
          when "new-reg" then LERB::Commands::NewReg
          when "reg" then LERB::Commands::Reg
          when "new-authz" then LERB::Commands::NewAuthz
          when "challenge" then LERB::Commands::Challenge
          when "new-cert" then LERB::Commands::NewCert
          when "cert" then LERB::Commands::Cert
          else
            show_help
            exit
        end
      end

      def show_help
        puts <<-END.unindent
          usage: lerb.rb command [options]

          where command is one of:
            new-reg         register for a new account
            reg             get account registration details
            new-authz       authorize account to manage certificates for a domain
            challenge       respond to a challenge to prove control of a domain
            new-cert        request a certificate
            cert            download certificate

          run lerb.rb command --help for command-specific information.
        END
      end

      def parse_args(args)
        parser = MyOptionParser.new(@command_name) do |p|
          command_class.add_command_options(p)
        end

        parser.parse(args)
      end

      def build_client
        uri = "https://acme-staging.api.letsencrypt.org/directory"
        account_key = LERB::AccountKey.new(@options[:account_key])

        LERB::Client.new(uri, account_key).tap do |c|
          c.set_debug if @options[:debug]
        end
      end
  end

  class MyOptionParser
    def initialize(command_name, &block)
      @parser = OptionParser.new
      @options = { }
      @required = [ ]

      @parser.separator ""
      @parser.separator "common options:"

      opt "--account-key=PATH", "private RSA key used for authentication", "(defaults to ~/.lerb/account_key)"
      opt "--json", "output JSON responses from server"
      opt "--script", "output script-friendly export commands"
      opt "--debug", "output HTTP debugging info"

      @parser.on "--version", "print version number" do
        puts "0.0.1"
        exit
      end

      @parser.on "--help", "display this message" do
        puts @parser
        exit
      end

      @parser.separator ""
      @parser.separator "#{command_name} command options:"

      yield(self)

      @parser.banner = "usage: lerb.rb #{command_name} #{@required.join(" ")} [options]"
    end

    def opt(long, *args)
      add_switch(false, long, args)
    end

    def req(long, *args)
      add_switch(true, long, args)
    end

    def parse(args)
      @parser.parse(args)

      if missing_required_argument?
        puts @parser.to_s
        exit
      end

      Hash[
        @options.collect do |k, v|
          [ long_to_key(k), v ]
        end
      ]
    end

    private

      def add_switch(required, long, args)
        @required << long if required
        @parser.on(long, *args) { |v| @options[long] = v }
      end

      def missing_required_argument?
        ( @required - @options.keys ).any?
      end

      def long_to_key(long)
        long.gsub(/^--/, '').gsub('-', '_').gsub(/=.*/, '').to_sym
      end
  end

  class OutputFormatter
    def initialize(client, options, result)
      @client = client
      @options = options
      @result = result
    end

    def run
      case
        when @options[:json] then json
        when @options[:script] then script
        else human
      end
    end

    def json
      @result.to_json
    end

    def human
      json
    end

    def script
    end
  end

  module Commands

    class NewReg
      def self.add_command_options(p)
        p.opt "--email=EMAIL", "contact email address"
        p.opt "--agreement=URI", "agree to the terms of service"
      end

      def run(client, options)
        hash = { }
        hash[:contact] = [ "mailto:#{options[:email]}" ] if options[:email]
        hash[:agreement] = options[:agreement] if options[:agreement]

        client.new_reg(hash)
      end

      class Output < OutputFormatter
        def human
          puts case @result[:code]
            when "201" then "Your account has been created."
            when "409" then "An account already exists for the supplied account key."
          end
        end
      end
    end

    class Reg
      def self.add_command_options(p)
        p.opt "--email=EMAIL", "contact email address"
        p.opt "--agreement=URI", "agree to the terms of service"
      end

      def run(client, options)
        hash = { }
        hash[:contact] = [ "mailto:#{options[:email]}" ] if options[:email]
        hash[:agreement] = options[:agreement] if options[:agreement]

        client.reg(hash)
      end

      class Output < OutputFormatter
      end
    end

    class NewAuthz
      def self.add_command_options(p)
        p.req "--domain=DOMAIN", "domain name for which to request authorization"
      end

      def run(client, options)
        client.new_authz(options[:domain])
      end

      class Output < OutputFormatter
        def human
          puts <<-END.unindent
            The authorization has been created.  You must perform one of the following
            challenges to prove control of the domain:

            #{challenges.join("\n\n")}
          END
        end

        def script
          vars = { }

          @result[:body]["challenges"].each do |c|
            vars["challenge_#{c["type"]}_token"] = c["token"]
            vars["challenge_#{c["type"]}_keyauth"] = @client.key_authorization(c["token"])
            vars["challenge_#{c["type"]}_uri"] = c["uri"]
          end

          vars.each do |k, v|
            k = k.gsub('-', '_').upcase
            puts "export LERB_#{Shellwords.escape(k)}=#{Shellwords.escape(v)}"
          end
        end

        private

          def challenges
            @result[:body]["challenges"].map do |challenge|
              header(challenge) + "\n\n" + instructions(challenge)
            end
          end

          def header(challenge)
            "---[ #{challenge["type"]} ]".ljust(78, "-")
          end

          def instructions(challenge)
            case challenge["type"]
              when /^dns/ then dns_challenge(challenge)
              when /^http/ then http_challenge(challenge)
              when /^tls-sni/ then tls_sni_challenge(challenge)
            end
          end

          def dns_challenge(challenge)
            "No instructions available."
          end

          def http_challenge(challenge)
            <<-END.unindent.strip_blank_account_key
              Ensure that the following URI:

                http://#{@options[:domain]}/.well-known/acme-challenge/#{challenge["token"]}

              returns the following data:

                #{@client.key_authorization(challenge["token"])}

              and then respond to the challenge by issuing the following command:

                ./lerb.rb challenge \\
                  --account-key=#{@options[:account_key]}
                  --uri=#{challenge["uri"]} \\
                  --type=#{challenge["type"]} \\
                  --token=#{challenge["token"]}
            END
          end

          def tls_sni_challenge(challenge)
            "No instructions available."
          end
      end
    end

    class Challenge
      def self.add_command_options(p)
        p.req "--uri=URI", "challenge URI"
        p.req "--type=TYPE", "type of challenge"
        p.req "--token=TOKEN", "challenge token"
      end

      def run(client, options)
        client.challenge(options[:uri], options[:type], options[:token])
      end

      class Output < OutputFormatter
      end
    end

    class NewCert
      def self.add_command_options(p)
        p.req "--csr=CSR", "CSR in either PEM or DER format"
      end

      def run(client, options)
        csr = OpenSSL::X509::Request.new(File.read(options[:csr]))
        client.new_cert(csr.to_der)
      end

      class Output < OutputFormatter
        def human
          puts <<-END.unindent
            issuer certificate:\n
            #{ca_cert}\n
            certificate:\n
            #{cert}\n
            certificate URI:\n
            #{@result[:location]}\n
          END
        end

        private

          def ca_cert
            data = open(@result[:links]["up"]).read
            OpenSSL::X509::Certificate.new(data).to_pem
          end

          def cert
            data = Base64.decode64(@result[:body])
            OpenSSL::X509::Certificate.new(data).to_pem
          end
      end
    end

    class Cert
      def self.add_command_options(p)
      end

      def run(client, options)
      end

      class Output < OutputFormatter
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

    def set_debug
      @http.set_debug_output(STDOUT)
    end

    def new_reg(hash)
      execute(directory["new-reg"], hash.merge(resource: "new-reg")).tap do
        agree_to_tos!
      end
    end

    def reg(hash)
      execute registration_uri, hash.merge(resource: "reg")
    end

    def new_authz(domain)
      agree_to_tos!
      execute directory["new-authz"],
        resource: "new-authz",
        identifier: {
          type: "dns",
          value: domain
        }
    end

    def challenge(uri, type, token)
      agree_to_tos!
      execute uri,
        resource: "challenge",
        type: type,
        keyAuthorization: key_authorization(token)
    end

    def new_cert(csr)
      agree_to_tos!
      execute directory["new-cert"],
        resource: "new-cert",
        csr: Helper.b64(csr)
    end

    def key_authorization(token)
      KeyAuthorization.new(@account_key).build(token)
    end

    def agree_to_tos!
      result = reg({})

      current = result[:links]["terms-of-service"]
      signed = result[:body]["agreement"]

      if signed != current
        reg(agreement: current)
      end
    end

    private

      def directory
        @directory ||= JSON.parse(open(@uri.to_s).read)
      end

      def execute(uri, payload)
        request = Net::HTTP::Post.new(uri)
        request.body = LERB::JWS.new(@account_key, nonce, payload.to_json).build
        response = @http.request(request)

        {
          code: response.code,
          headers: response.to_hash,
          location: response["Location"],
          links: links(response),
          body: ( JSON.parse(response.body) rescue Base64.encode64(response.body) )
        }
      end

      def links(response)
        if links = response["Link"]
          Hash[links.scan(/\<(.+?)\>\;rel="(.+?)"/)].invert
        else
          { }
        end
      end

      def nonce
        @http.request(Net::HTTP::Head.new(@uri))["Replay-Nonce"]
      end

      def registration_uri
        @registration_uri ||= begin
          result = execute(directory["new-reg"], resource: "new-reg")
          result[:location]
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
      @path = File.expand_path(path || AccountKey.default_path)
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

LERB::CLI.new(ARGV).run

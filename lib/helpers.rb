require 'ghee'
require 'aead'
require 'securerandom'
#require 'rack-cache'
#require 'active_support/cache'
require_relative 'bridge/huboard'
require_relative 'couch/client'

class Huboard
  module Common
    module Helpers

      def couch
        @couch ||= Huboard::Couch.new :base_url => ENV["COUCH_URL"], :database => ENV["COUCH_DATABASE"]
      end


      NONCE_LENGTH = 12

      # we don't use aead's nonce generation because it basically keeps a
      # counter which needs to be persisted on disk. This is probably to
      # defend against nonce collision scenarios for extremely high nonce/s
      # scenarios, but at the rate we're generating nonces the chance of a
      # collission should be minuscle, namely roughly ~ `(u*n)^2/(2*(2^8)^12)`
      # where `u` is the number of users and `n` is the number of times we
      # generate a token for per user. So the likelihood that something goes
      # wrong with ensuring the persistence of the state file seems much
      # higher to me. We could cache user nonces in a running server session,
      # to basically keep `n` close to 1, but even that seems overkill.
      def generate_nonce
        SecureRandom.random_bytes(NONCE_LENGTH)
        # File.read("/dev/urandom", NONCE_LENGTH)
      end

      def cipher_class
        AEAD::Cipher.new('AES-256-GCM')
      end

      def secret_key
        Base64.decode64 settings.secret_key
      end


      def cipher
        cipher_class.new(secret_key)
      end

      def auth_data
         params[:user]
      end

      def encrypted_token
        Base64.urlsafe_encode64(encrypt_token(auth_data))
      end

      def encrypt_token(auth_data)
        return if !user_token
        nonce = generate_nonce
        "#{nonce}#{cipher.encrypt(nonce, auth_data, user_token)}" if user_token
      end

      def user_token
        github_user.token
      end

      def decrypt_token(noncetoken, auth_data)
        decoded = Base64.urlsafe_decode64(noncetoken)
        nonce = decoded[0...NONCE_LENGTH]
        token = decoded[NONCE_LENGTH..-1]
        cipher.decrypt(nonce, auth_data, token)
      end

      def check_token(token)
        ghee = gh token
        ghee.connection.get('/').status == 200
      end

      def current_user
        github_user
      end

      # The authenticated user object
      #
      # Supports a variety of methods, name, full_name, email, etc
      def github_user
        warden.user(:private) || warden.user || Hashie::Mash.new
      end

      def github
        @github ||= Stint::Github.new(gh)
      end

      def pebble
        @pebble ||= Stint::Pebble.new(github, huboard)
      end

      def h(input = "")
        ERB::Util.html_escape input
      end

      def huboard(token = nil)
        Huboard::Client.new(token || user_token, github_config)
      end

      def gh(token = nil)
        huboard(token).connection
      end

      def socket_backend
        return settings.socket_backend if settings.respond_to? :socket_backend
      end

      def publish(channel,event,payload)
        # no op
      end

      def json(obj)
        content_type :json
        JSON.pretty_generate(obj)
      end

      def base_url
        @base_url ||= "#{request.env['rack.url_scheme']}://#{request.env['HTTP_HOST']}"
      end

      def team_id
        settings.team_id
      end
    end
  end
end

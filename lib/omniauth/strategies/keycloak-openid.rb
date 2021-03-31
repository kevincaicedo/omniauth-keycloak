require 'omniauth'
require 'omniauth-oauth2'
require 'json/jwt'
require 'uri'

module OmniAuth
    module Strategies
        class KeycloakOpenId < OmniAuth::Strategies::OAuth2

            class Error < RuntimeError; end
            class ConfigurationError < Error; end
            class IntegrationError < Error; end

            attr_reader :authorize_url
            attr_reader :token_url
            attr_reader :cert
            attr_accessor :access_token

            def setup_phase
                if @authorize_url.nil? || @token_url.nil?
                    prevent_site_option_mistake

                    realm = options.client_options[:realm].nil? ? options.client_id : options.client_options[:realm]
                    site = options.client_options[:site]

                    raise_on_failure = options.client_options.fetch(:raise_on_failure, false)

                    config_url = URI.join(site, "/auth/realms/#{realm}/.well-known/openid-configuration")

                    log :debug, "Going to get Keycloak configuration. URL: #{config_url}"
                    response = Faraday.get config_url
                    if (response.status == 200)
                        json = MultiJson.load(response.body)

                        @certs_endpoint = json["jwks_uri"]
                        @userinfo_endpoint = json["userinfo_endpoint"]
                        @authorize_url = URI(json["authorization_endpoint"]).path
                        @token_url = URI(json["token_endpoint"]).path

                        log_config(json)

                        options.client_options.merge!({
                            authorize_url: @authorize_url,
                            token_url: @token_url
                                                      })
                        log :debug, "Going to get certificates. URL: #{@certs_endpoint}"
                        certs = Faraday.get @certs_endpoint
                        if (certs.status == 200)
                            json = MultiJson.load(certs.body)
                            @cert = json["keys"][0]
                            log :debug, "Successfully got certificate. Certificate length: #{@cert.length}"
                        else
                            message = "Coundn't get certificate. URL: #{@certs_endpoint}"
                            log :error, message
                            raise IntegrationError, message if raise_on_failure
                        end
                    else
                        message = "Keycloak configuration request failed with status: #{response.status}. " \
                                  "URL: #{config_url}"
                        log :error, message
                        raise IntegrationError, message if raise_on_failure
                    end
                end
            end

            def prevent_site_option_mistake
              site = options.client_options[:site]
              return unless site =~ /\/auth$/

              raise ConfigurationError, "Keycloak site parameter should not include /auth part, only domain. Current value: #{site}"
            end

            def log_config(config_json)
              log_keycloak_config = options.client_options.fetch(:log_keycloak_config, false)
              log :debug, "Successfully got Keycloak config"
              log :debug, "Keycloak config: #{config_json}" if log_keycloak_config
              log :debug, "Certs endpoint: #{@certs_endpoint}"
              log :debug, "Userinfo endpoint: #{@userinfo_endpoint}"
              log :debug, "Authorize url: #{@authorize_url}"
              log :debug, "Token url: #{@token_url}"
            end

            def callback_phase # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/MethodLength, Metrics/PerceivedComplexity
                error = request.params["error_reason"] || request.params["error"]
                if error
                  fail!(error, CallbackError.new(request.params["error"], request.params["error_description"] || request.params["error_reason"], request.params["error_uri"]))
                elsif !options.provider_ignores_state && (request.params["state"].to_s.empty? || request.params["state"] != session.delete("omniauth.state"))
                  fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
                else
                  self.access_token = build_access_token
                  self.access_token = access_token.refresh! if access_token.expired?
                  super
                  redirect "http://localhost:3333/oauth/recived?token=#{access_token.token}"
                end
            rescue ::OAuth2::Error, CallbackError => e
                fail!(:invalid_credentials, e)
            rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
                fail!(:timeout, e)
            rescue ::SocketError => e
                fail!(:failed_to_connect, e)
            end

            def build_access_token
                verifier = request.params["code"]
                token = client.auth_code.get_token(verifier, 
                    {:redirect_uri => callback_url.gsub(/\?.+\Z/, "")}
                    .merge(token_params.to_hash(:symbolize_keys => true)), 
                    deep_symbolize(options.auth_token_params))
                log :debug, "Test TK: #{token}"
                return token
            end

            # def other_phase
            #     log :debug, "Test TK: #{@access_token}"
            #     if @access_token.nil?
            #         redirect "http://localhost:3333/oauth/fails"
            #     else
            #         redirect "http://localhost:3333/oauth/recived?token=#{@access_token.token}"
            #     end
            # end

            uid{ raw_info['sub'] }
        
            info do
            {
                :name => raw_info['name'],
                :email => raw_info['email'],
                :first_name => raw_info['given_name'],
                :last_name => raw_info['family_name']
            }
            end
        
            extra do
            {
                'raw_info' => raw_info
            }
            end
        
            def raw_info
                id_token_string = access_token.token
                jwk = JSON::JWK.new(@cert)
                id_token = JSON::JWT.decode id_token_string, jwk
                id_token
            end

            OmniAuth.config.add_camelization('keycloak_openid', 'KeycloakOpenId')
        end
    end
end

package com.ginkgooai.core.gateway.security;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * A representation of an OAuth 2.0 Token Request for the client credentials grant
 * or other custom grant types.
 */
public class OAuth2TokenRequest {
    private final ClientRegistration clientRegistration;
    private final String grantType;
    private final Map<String, Object> additionalParameters;

    private OAuth2TokenRequest(ClientRegistration clientRegistration, String grantType, 
                              Map<String, Object> additionalParameters) {
        Assert.notNull(clientRegistration, "clientRegistration cannot be null");
        Assert.hasText(grantType, "grantType cannot be empty");
        this.clientRegistration = clientRegistration;
        this.grantType = grantType;
        this.additionalParameters = additionalParameters != null 
                ? new HashMap<>(additionalParameters) : new HashMap<>();
    }

    /**
     * Returns the client registration.
     * @return the client registration
     */
    public ClientRegistration getClientRegistration() {
        return this.clientRegistration;
    }

    /**
     * Returns the grant type.
     * @return the grant type
     */
    public String getGrantType() {
        return this.grantType;
    }

    /**
     * Returns the additional parameters.
     * @return the additional parameters
     */
    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }

    /**
     * Returns a new builder for an {@link OAuth2TokenRequest}.
     * @param clientRegistration the client registration
     * @return a builder
     */
    public static Builder withClientRegistration(ClientRegistration clientRegistration) {
        return new Builder(clientRegistration);
    }

    /**
     * A builder for {@link OAuth2TokenRequest}.
     */
    public static class Builder {
        private final ClientRegistration clientRegistration;
        private String grantType;
        private Map<String, Object> additionalParameters;

        private Builder(ClientRegistration clientRegistration) {
            this.clientRegistration = clientRegistration;
        }

        /**
         * Sets the grant type.
         * @param grantType the grant type
         * @return the builder
         */
        public Builder grantType(String grantType) {
            this.grantType = grantType;
            return this;
        }

        /**
         * Adds additional parameters using the provided {@code Consumer}.
         * @param additionalParametersConsumer the consumer for the additional parameters
         * @return the builder
         */
        public Builder additionalParameters(Consumer<Map<String, Object>> additionalParametersConsumer) {
            if (this.additionalParameters == null) {
                this.additionalParameters = new HashMap<>();
            }
            additionalParametersConsumer.accept(this.additionalParameters);
            return this;
        }

        /**
         * Builds a new {@link OAuth2TokenRequest}.
         * @return an {@link OAuth2TokenRequest}
         */
        public OAuth2TokenRequest build() {
            return new OAuth2TokenRequest(this.clientRegistration, this.grantType, this.additionalParameters);
        }
    }
}

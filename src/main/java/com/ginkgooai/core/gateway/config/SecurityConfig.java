package com.ginkgooai.core.gateway.config;

import com.ginkgooai.core.gateway.filter.ShareCodeAuthenticationFilter;
import com.ginkgooai.core.gateway.security.ProblemDetailsAuthenticationEntryPoint;
import com.ginkgooai.core.gateway.security.ShareCodeAuthorizationRequestResolver;
import com.ginkgooai.core.gateway.security.ShareCodeGrantRequestEntityConverter;
import com.ginkgooai.core.gateway.security.ShareCodeTokenResponseClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.net.URI;
import java.util.LinkedHashMap;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Value("${app.base-uri}")
    private String appBaseUri;

    @Value("${app.domain-name}")
    private String domainName;

    @Value("${app.api-uri}")
    private String apiBaseUri;

    @Value("${auth-server-uri}")
    private String authServerUri;

    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {
        DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, "/oauth2/authorization");

        // Enable PKCE
        // resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        return resolver;
    }

    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   AuthenticationConfiguration authenticationConfiguration,
                                                   OAuth2AuthorizationRequestResolver authorizationRequestResolver,
                                                   ClientRegistrationRepository clientRegistrationRepository,
                                                   OAuth2AuthorizedClientService authorizedClientService) throws Exception {

        CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        cookieCsrfTokenRepository.setCookieCustomizer(cookie -> cookie.domain(domainName));
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        csrfTokenRequestAttributeHandler.setCsrfRequestAttributeName(null);

        ShareCodeTokenResponseClient tokenResponseClient = new ShareCodeTokenResponseClient();

        ShareCodeAuthenticationFilter shareCodeFilter = new ShareCodeAuthenticationFilter(
                clientRegistrationRepository,
                authorizedClientService,
                tokenResponseClient,
                "ginkgoo-web-client",
                appBaseUri);

        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                // .csrf(csrf ->
                // csrf
                // .csrfTokenRepository(cookieCsrfTokenRepository)
                // .csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                // .ignoringRequestMatchers("/logout")
                // )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/health",
                                "/login",
                                "/error",
                                // Swagger
                                "/swagger-ui/**",
                                "/v3/api-docs/**",
                                "/api/*/v3/api-docs/**",
                                "/api/messaging/webhook")
                        .permitAll()
                    .requestMatchers("/api/oauth2/guest").permitAll() // Allow guest code entry
                        .anyRequest().authenticated())
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .maximumSessions(1)
                        .sessionRegistry(sessionRegistry())
                        .maxSessionsPreventsLogin(false))
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new ProblemDetailsAuthenticationEntryPoint())
                        .accessDeniedHandler(new ProblemDetailsAuthenticationEntryPoint()))
                .oauth2Login(oauth2Login -> oauth2Login
                        .loginPage("/login")
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(
                                    new ShareCodeAuthorizationRequestResolver(
                                                clientRegistrationRepository,
                                                "/oauth2/authorization",
                                                "ginkgoo-web-client"))

                        )
                        .tokenEndpoint(token -> token
                                .accessTokenResponseClient(accessTokenResponseClient()))
                        .successHandler(new SimpleUrlAuthenticationSuccessHandler(
                                "/authorized"))
                        .failureHandler(new SimpleUrlAuthenticationFailureHandler(
                                "/login?error=true")))
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler(logoutHandler(cookieCsrfTokenRepository))
                        // .logoutSuccessHandler(new
                        // HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
                        .logoutSuccessHandler(
                                oidcLogoutSuccessHandler(clientRegistrationRepository))
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .deleteCookies("SESSION")
                        .clearAuthentication(true))
                .oauth2Client(oauth2Client -> oauth2Client
                        .authorizationCodeGrant(codeGrant -> codeGrant
                                .authorizationRequestResolver(
                                        authorizationRequestResolver)
                                .authorizationRequestRepository(
                                        authorizationRequestRepository())))
            .addFilterBefore(shareCodeFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
        client.setRequestEntityConverter(new ShareCodeGrantRequestEntityConverter());
        return client;
    }

    private AuthenticationEntryPoint authenticationEntryPoint() {
        AuthenticationEntryPoint authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(
                "/oauth2/authorization/ginkgoo-web-client");
        MediaTypeRequestMatcher textHtmlMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
        textHtmlMatcher.setUseEquals(true);

        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
        entryPoints.put(textHtmlMatcher, authenticationEntryPoint);

        DelegatingAuthenticationEntryPoint delegatingAuthenticationEntryPoint = new DelegatingAuthenticationEntryPoint(
                entryPoints);
        delegatingAuthenticationEntryPoint.setDefaultEntryPoint(
                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
        return delegatingAuthenticationEntryPoint;
    }

    private LogoutHandler logoutHandler(CsrfTokenRepository csrfTokenRepository) {
        return new CompositeLogoutHandler(
                new SecurityContextLogoutHandler(),
                new CsrfLogoutHandler(csrfTokenRepository));
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler(
            ClientRegistrationRepository clientRegistrationRepository) {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(
                clientRegistrationRepository);

        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create(apiBaseUri).toString());

        return oidcLogoutSuccessHandler;
    }
}
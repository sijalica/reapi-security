//package com.reapi.securityAPI.config;
//
//import com.nimbusds.jose.jwk.JWKSet;
//import com.nimbusds.jose.jwk.RSAKey;
//import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
//import com.nimbusds.jose.jwk.source.JWKSource;
//import com.nimbusds.jose.proc.SecurityContext;
//
//import com.reapi.securityAPI.repository.LdapRegisteredClientRepository;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.core.io.Resource;
//import org.springframework.http.MediaType;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.oauth2.core.AuthorizationGrantType;
//import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
//import org.springframework.security.oauth2.core.oidc.OidcScopes;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
//import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
//import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
//import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
//import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
//import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
//
//import java.io.InputStream;
//import java.security.KeyStore;
//import java.security.interfaces.RSAPrivateKey;
//import java.security.interfaces.RSAPublicKey;
//import java.util.UUID;
//
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//    @Value("${jwt.keystore.location}")
//    private Resource keystore;
//
//    @Value("${jwt.keystore.password}")
//    private String keystorePassword;
//
//    @Value("${jwt.keystore.alias}")
//    private String keyAlias;
//
//    private final LdapRegisteredClientRepository ldapRegisteredClientRepository;
//
//    public SecurityConfig(LdapRegisteredClientRepository ldapRegisteredClientRepository) {
//        this.ldapRegisteredClientRepository = ldapRegisteredClientRepository;
//    }
//
//    @Bean
//    @Order(1)
//    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
//            throws Exception {
//        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
//                OAuth2AuthorizationServerConfigurer.authorizationServer();
//
//        http
//                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
//                .with(authorizationServerConfigurer, authorizationServer ->
//                        authorizationServer
//                                .oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
//                )
//                .authorizeHttpRequests(authorize ->
//                        authorize
//                                .anyRequest().authenticated()
//                )
//                // Redirect to the login page when not authenticated from the
//                // authorization endpoint
//                .exceptionHandling(exceptions -> exceptions
//                        .defaultAuthenticationEntryPointFor(
//                                new LoginUrlAuthenticationEntryPoint("/login"),
//                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
//                        )
//                );
//
//        return http.build();
//    }
//
//    @Bean
//    @Order(2)
//    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
//            throws Exception {
//        http
//                .authorizeHttpRequests(authorize -> authorize
//                        .anyRequest().authenticated()
//                )
//                // Form login handles the redirect to the login page from the
//                // authorization server filter chain
//                .formLogin(Customizer.withDefaults());
//
//        return http.build();
//    }
//
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("password")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }
//
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
////        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
////                .clientId("oidc-client")
////                .clientSecret("{noop}secret")
////                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
////                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
////                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
////                .redirectUri("https://oauth.pstmn.io/v1/callback")
////                .postLogoutRedirectUri("http://127.0.0.1:8080/")
////                .scope(OidcScopes.OPENID)
////                .scope(OidcScopes.PROFILE)
////                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
////                .build();
//
//        // Fetch the client details from LDAP or create new ones
//        RegisteredClient registeredClient = ldapRegisteredClientRepository.findByClientId("oidc-client")
//                .orElseThrow(() -> new RuntimeException("Client not found"));
//
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }
//
//    @Bean
//    public JWKSource<SecurityContext> jwkSource() throws Exception {
//        // 1. Load the JKS keystore from the classpath
//        KeyStore store = KeyStore.getInstance("JKS");
//        try (InputStream in = keystore.getInputStream()) {
//            store.load(in, keystorePassword.toCharArray());
//        }
//
//        // 2. Extract the RSA key pair
//        RSAPrivateKey privateKey = (RSAPrivateKey) store.getKey(keyAlias, keystorePassword.toCharArray());
//        RSAPublicKey publicKey = (RSAPublicKey) store.getCertificate(keyAlias).getPublicKey();
//
//        // 3. Build a Nimbus RSAKey (a JWK) with a random key ID
//        RSAKey rsaJwk = new RSAKey.Builder(publicKey)
//                .privateKey(privateKey)
//                .keyID(UUID.randomUUID().toString())
//                .build();
//
//        // 4. Expose as an immutable JWK set
//        JWKSet jwkSet = new JWKSet(rsaJwk);
//        return new ImmutableJWKSet<>(jwkSet);
//    }
//
//    @Bean
//    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
//        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
//    }
//
//    @Bean
//    public AuthorizationServerSettings authorizationServerSettings() {
//        return AuthorizationServerSettings.builder().build();
//    }
//
//}
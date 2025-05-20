package com.reapi.securityAPI.config;

import com.reapi.securityAPI.util.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
public class SecurityConfigJWT {

//    @Bean
//    public UserDetailsService userDetailsService(PasswordEncoder encoder) {
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        manager.createUser(
//                User.withUsername("user")
//                        .password(encoder.encode("password"))
//                        .roles("USER")
//                        .build()
//        );
//        manager.createUser(
//                User.withUsername("admin")
//                        .password(encoder.encode("adminpass"))
//                        .roles("ADMIN")
//                        .build()
//        );
//        return manager;
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtUtil);

        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                        .anyRequest().authenticated()
                )
        //        .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
        ;

        return httpSecurity.build();
    }

    @Bean
    public LdapAuthenticationProvider ldapAuthenticationProvider() {
        DefaultSpringSecurityContextSource contextSource =
                new DefaultSpringSecurityContextSource("ldap://localhost:389/dc=myorg,dc=com");
        contextSource.setUserDn("cn=ROLE_USER,ou=groups,dc=myorg,dc=com");
        contextSource.setPassword("admin");

        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        authenticator.setUserDnPatterns(new String[]{"uid={0},ou=people"});

        return new LdapAuthenticationProvider(authenticator);
    }

    @Bean
    public AuthenticationManager authenticationManager(LdapAuthenticationProvider ldapAuthProvider) {
        return new ProviderManager(ldapAuthProvider);
    }
}

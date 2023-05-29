package com.bunthong.friendlyjwt.configuration;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    //user credentail
    //securityFilter chain -> security configuration
    //password encoder
    private final UserDetailsService userDetailsService;

//    @Bean
//    public InMemoryUserDetailsManager userDetailsManager(){
//        UserDetails user = User.builder()
//                .username("Benzz")
//                .password("{noop}12345")
//                .authorities("UserAccount:read", "UserAccount:write").build();
//
//                return new InMemoryUserDetailsManager(user);
//    }
    @Bean
    @Deprecated(since = "6.1", forRemoval = true)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
http.authorizeHttpRequests().anyRequest().permitAll();

        try {
            http.csrf(AbstractHttpConfigurer::disable)
                    .authorizeHttpRequests(request -> request.anyRequest().authenticated())
                    .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .httpBasic(Customizer.withDefaults());
            return http.build();
        }catch (Exception ex){
            System.out.println("Exception Occurs: " + ex.getMessage());
            return null;
        }
    }
@Bean
public AuthenticationManager manager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
}
@Bean
public RSAKey rsaKey(KeyPair keyPair){
        return  new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair().getPrivate())
                .keyID(UUID.randomUUID().toString()).build();
}
//@Bean
//public NoOpPasswordEncoder passwordEncoder(){
//        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
//}

@Bean
public DaoAuthenticationProvider provider() throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(new BCryptPasswordEncoder());
        return provider;
}

    //1. keyPair
    @Bean
    public KeyPair keyPair(){
        try{
            var keyGenerator = KeyPairGenerator.getInstance("RSA");
            keyGenerator .initialize(2048);
            return keyGenerator.generateKeyPair();

        }catch (NoSuchAlgorithmException ex ){
            throw new RuntimeException();
        }
    }

    //3. encoder
    @Bean
    public NimbusJwtEncoder jwtEncoder(){
        // create instance of jwk
        JWK jwk =new RSAKey.Builder((RSAPublicKey) keyPair().getPublic()).privateKey(keyPair().getPrivate()).build();
        // provide that instance to the jwksource
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);

    }
    //4. Decoder
    @Bean
    public JwtDecoder jwtDecoder(){
        return  NimbusJwtDecoder.withPublicKey((RSAPublicKey) keyPair().getPublic()).build();
    }
    //2. rsakey
    //
    // */
}

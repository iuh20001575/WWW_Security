package vn.edu.iuh.fit.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    public void globalConfig(AuthenticationManagerBuilder managerBuilder, PasswordEncoder encoder) throws Exception {
        managerBuilder.inMemoryAuthentication()
                .withUser(User.withUsername("a").password(encoder.encode("a")).roles("ADMIN").build())
                .withUser(User.withUsername("b").password(encoder.encode("b")).roles("USER").build())
                .withUser(User.withUsername("c").password(encoder.encode("c")).roles("ADMIN", "USER").build());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(auth ->
            auth
                    .requestMatchers("/", "/index", "/home").permitAll()
                    .requestMatchers("/api", "/api/**").hasAnyRole("ADMIN", "USER")
                    .requestMatchers("/dashboard", "/dashboard/**").hasRole("ADMIN")
                    .requestMatchers("/users", "/users/**").hasRole("USER")
                    .anyRequest().authenticated()
        );

        httpSecurity.httpBasic(Customizer.withDefaults());
        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

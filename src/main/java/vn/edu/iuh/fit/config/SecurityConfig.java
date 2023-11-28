package vn.edu.iuh.fit.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
public class SecurityConfig {
    @Autowired
    public void globalConfig(AuthenticationManagerBuilder managerBuilder, DataSource dataSource) throws Exception {
        PasswordEncoder encoder = new BCryptPasswordEncoder();

        managerBuilder.jdbcAuthentication()
                .dataSource(dataSource)
                .withDefaultSchema()
                .withUser(User.withUsername("a").password(encoder.encode("a")).roles("ADMIN").build())
                .withUser(User.withUsername("b").password(encoder.encode("b")).roles("USER").build())
                .withUser(User.withUsername("c").password(encoder.encode("c")).roles("ADMIN", "USER").build());
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(auth ->
                auth
                        .requestMatchers("/api", "/api/**").permitAll()
                        .requestMatchers("/dashboard", "/dashboard/**").hasRole("ADMIN")
                        .requestMatchers("/users", "/users/**").hasRole("USER")
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/", "/index", "/home").permitAll()
                        .requestMatchers("/api/v1/auth/**", "/v2/api-docs/**", "/v3/api-docs/**",
                                "/swagger-resources/**", "/swagger-ui/**", "/webjars/**").permitAll()
                        .anyRequest().permitAll()
        );

        httpSecurity.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"));
        httpSecurity.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        httpSecurity.csrf(AbstractHttpConfigurer::disable);

        httpSecurity.httpBasic(Customizer.withDefaults());
        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

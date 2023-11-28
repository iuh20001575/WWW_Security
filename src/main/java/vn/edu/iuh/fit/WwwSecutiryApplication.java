package vn.edu.iuh.fit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import vn.edu.iuh.fit.services.JdbcUserServices;

@SpringBootApplication
public class WwwSecutiryApplication {
    @Autowired
    private JdbcUserServices jdbcUserServices;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public static void main(String[] args) {
        SpringApplication.run(WwwSecutiryApplication.class, args);
    }

    @Bean
    CommandLineRunner add() {
        return args -> {
            UserDetails userDetails = User.withUsername("d")
                    .password(passwordEncoder.encode("d"))
                    .roles("ADMIN", "USER")
                    .build();

            jdbcUserServices.add(userDetails);
        };
    }
}

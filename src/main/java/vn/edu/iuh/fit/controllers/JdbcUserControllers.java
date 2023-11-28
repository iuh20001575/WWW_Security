package vn.edu.iuh.fit.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import vn.edu.iuh.fit.dto.AuthInfos;
import vn.edu.iuh.fit.dto.UserInfo;
import vn.edu.iuh.fit.services.JdbcUserServices;

import java.security.Principal;

@RestController
@RequestMapping("/api/users")
public class JdbcUserControllers {
    private final JdbcUserServices jdbcUserServices;
    private final PasswordEncoder passwordEncoder;

    public JdbcUserControllers(JdbcUserServices jdbcUserServices, PasswordEncoder passwordEncoder) {
        this.jdbcUserServices = jdbcUserServices;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping(value = {"", "/", "/add"})
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> insert(@RequestBody UserInfo userInfo) {
        UserDetails userDetails = User.withUsername(userInfo.username())
                .password(passwordEncoder.encode(userInfo.password()))
                .roles(userInfo.authorities())
                .disabled(!userInfo.enabled())
                .build();

        return ResponseEntity.ok(jdbcUserServices.add(userDetails));
    }

    @GetMapping("/{username}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> get(@PathVariable("username") String username) {
        try {
            UserDetails userDetails = jdbcUserServices.find(username);

            return ResponseEntity.ok(userDetails);
        } catch (Exception ignored) {

        }

        return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
    }

    @PatchMapping("")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<?> changePassword(Principal principal, @RequestBody String password) {
        return ResponseEntity.ok(jdbcUserServices.updatePassword(principal.getName(), passwordEncoder.encode(password)));
    }

    @DeleteMapping("/{username}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> delete(@PathVariable("username") String username) {
        try {
            UserDetails userDetails = jdbcUserServices.delete(username);

            return ResponseEntity.ok(userDetails);
        } catch (Exception ignored) {

        }

        return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
    }

    @GetMapping("/principal")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<?> retrievePrincipal(Principal principal, Authentication authentication) {
        return ResponseEntity.ok(new AuthInfos(principal, authentication));
    }
}

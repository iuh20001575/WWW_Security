package vn.edu.iuh.fit.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/password")
public class PasswordGenResources {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/gen")
    public String genPassword(@RequestParam("password") String password) {
        return passwordEncoder.encode(password);
    }
}

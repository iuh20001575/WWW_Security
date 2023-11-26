package vn.edu.iuh.fit.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/users")
public class UsersResources {
    @GetMapping("")
    public String index() {
        return "users/index";
    }
}

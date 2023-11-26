package vn.edu.iuh.fit.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/dashboard")
public class DashboardResources {
    @GetMapping("")
    public String index() {
        System.out.println("test=====================");

        return "dashboard/index";
    }
}

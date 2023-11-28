package vn.edu.iuh.fit.dto;

public record UserInfo(String username, String password, boolean enabled, String[] authorities) {}

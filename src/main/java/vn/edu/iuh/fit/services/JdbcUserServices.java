package vn.edu.iuh.fit.services;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;

@Service
@Getter @Setter
public class JdbcUserServices {
    private final JdbcUserDetailsManager manager;
    private DataSource dataSource;

    public JdbcUserServices(DataSource dataSource) {
        this.dataSource = dataSource;
        manager = new JdbcUserDetailsManager(dataSource);
    }

    public UserDetails add(UserDetails userDetails) {
        manager.createUser(userDetails);

        return userDetails;
    }

    public UserDetails find(String username) {
        return manager.loadUserByUsername(username);
    }

    public UserDetails updatePassword(String username, String password) {
        UserDetails user = manager.loadUserByUsername(username);
        manager.changePassword("noop", password);

        return user;
    }

    public UserDetails delete(String username) {
        UserDetails userDetails = manager.loadUserByUsername(username);
        manager.deleteUser(username);

        return userDetails;
    }

    public UserDetails updateRoles(String username, String[] roles) {
        UserDetails userDetails = manager.loadUserByUsername(username);

        UserDetails user = User.withUserDetails(userDetails)
                .roles(roles).build();

        manager.updateUser(user);

        return user;
    }
}

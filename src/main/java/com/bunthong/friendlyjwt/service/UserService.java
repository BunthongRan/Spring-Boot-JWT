package com.bunthong.friendlyjwt.service;

import com.bunthong.friendlyjwt.model.UserAccount;
import com.bunthong.friendlyjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {
    @Autowired
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserAccount user =userRepository.getAllUsers(username);

        return User.builder()
                .username(user.getUsername())
                .password(user.getPasscode())
                .roles("USER")
                .build();
    }
}

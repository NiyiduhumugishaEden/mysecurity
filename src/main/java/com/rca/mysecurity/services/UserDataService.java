package com.rca.mysecurity.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.rca.mysecurity.entity.UserData;
import com.rca.mysecurity.repository.IUserDataRepository;
import java.util.List;
import java.util.Optional;

@Service
public class UserDataService implements UserDetailsService {
    @Autowired
    private IUserDataRepository repository;

    @Autowired
    private  PasswordEncoder encoder;

//    @Autowired
//    public UserDataService(IUserDataRepository repository, @Lazy PasswordEncoder encoder) {
//        this.repository = repository;
//        this.encoder = encoder;
//    }

    public UserDataService() {

    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<UserData> userData = repository.findByEmail(username);
        return userData.map(UserDataDetails::new)
                .orElseThrow(() -> new UsernameNotFoundException("User not found " + username));
    }

    public UserData loadCurrentUser(String username) throws UsernameNotFoundException {
        Optional<UserData> userDetail = repository.findByEmail(username);
        return userDetail
                .orElseThrow(() -> new UsernameNotFoundException("User not found " + username));
    }

    public String addUser(UserData userData) {
        userData.setPassword(encoder.encode(userData.getPassword()));
        repository.save(userData);
        return "User Added Successfully";
    }

    public List<UserData> listAll() {
        return repository.findAll();
    }
}

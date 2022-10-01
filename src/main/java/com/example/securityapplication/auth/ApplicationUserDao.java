package com.example.securityapplication.auth;

import com.example.securityapplication.auth.ApplicationUser;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> selectApplicationUserByUsername(String username);

}

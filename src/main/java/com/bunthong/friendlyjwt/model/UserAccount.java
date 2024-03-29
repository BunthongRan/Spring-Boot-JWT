package com.bunthong.friendlyjwt.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class UserAccount {
    private int id;
    private String username;
    private String email;
    private String passcode;
    private String gender;
    private String address;
    private String role;
}

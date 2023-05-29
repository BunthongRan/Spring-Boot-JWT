package com.bunthong.friendlyjwt.repository;

import com.bunthong.friendlyjwt.model.UserAccount;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.Mapping;

@Repository
@Mapper
public interface UserRepository {
    @Select("select * from account_tb where username like #{username}")

    UserAccount getAllUsers(String username);
}

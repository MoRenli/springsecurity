package com.lkjedu.boot.service;

import com.lkjedu.boot.beans.UserBean;
import com.lkjedu.boot.mappers.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service()
public class MyUserDetailsService implements UserDetailsService {
    @Resource
    private UserMapper userMapper;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserBean byId = userMapper.findById(username);
        if (byId != null){
            //用户密码加密
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            String password = passwordEncoder.encode(byId.getPassword());

            //添加用户角色
            List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admin");

            User user = new User(byId.getUserName(), password, auths);
            return user;
        }
        throw new UsernameNotFoundException("用户名或者密码错误~");
    }
}

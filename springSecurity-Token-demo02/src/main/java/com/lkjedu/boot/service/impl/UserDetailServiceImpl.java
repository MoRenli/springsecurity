package com.lkjedu.boot.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.lkjedu.boot.beans.UserBean;
import com.lkjedu.boot.domain.LoginUser;
import com.lkjedu.boot.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class UserDetailServiceImpl implements UserDetailsService {
    @Autowired
    private UserMapper userMapper;
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        //查询用户信息
        QueryWrapper<UserBean> wrapper = new QueryWrapper<>();
        QueryWrapper<UserBean> userName = wrapper.eq("userName", s);
        UserBean userBean = userMapper.selectOne(userName);
        if (userBean == null){
            throw new RuntimeException("用户名或者密码错误~~~~");
        }
        //把数据封装成UserDetails返回出去

        //TODO 查询对应的权限信息
        ArrayList<String> authenticationList = new ArrayList<>();
        authenticationList.add("admin");
        authenticationList.add("ROLE_aaa");
        return new LoginUser(userBean,authenticationList);
    }
}

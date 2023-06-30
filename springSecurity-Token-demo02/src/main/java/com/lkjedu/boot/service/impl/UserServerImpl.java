package com.lkjedu.boot.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.lkjedu.boot.beans.UserBean;
import com.lkjedu.boot.mapper.UserMapper;
import com.lkjedu.boot.service.UserService;
import org.springframework.stereotype.Service;

@Service
public class UserServerImpl extends ServiceImpl<UserMapper, UserBean> implements UserService {
}

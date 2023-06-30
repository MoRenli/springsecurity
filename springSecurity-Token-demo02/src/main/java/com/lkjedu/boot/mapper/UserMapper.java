package com.lkjedu.boot.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.lkjedu.boot.beans.UserBean;

import java.util.List;

public interface UserMapper extends BaseMapper<UserBean> {
    List<UserBean> selectAll();
}

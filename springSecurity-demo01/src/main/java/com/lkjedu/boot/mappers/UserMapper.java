package com.lkjedu.boot.mappers;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.lkjedu.boot.beans.UserBean;
import org.apache.ibatis.annotations.Param;

public interface UserMapper extends BaseMapper<UserBean> {
    UserBean findById(@Param("userName")String userName);
}

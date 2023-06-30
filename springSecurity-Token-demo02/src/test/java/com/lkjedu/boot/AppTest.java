package com.lkjedu.boot;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.lkjedu.boot.beans.UserBean;
import com.lkjedu.boot.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Unit test for simple App.
 */
@SpringBootTest
public class AppTest {
    /**
     * Rigorous Test :-)
     */
    @Autowired
    private UserMapper userMapper;
    @Test
    public void shouldAnswerWithTrue() {
        QueryWrapper<UserBean> wrapper = new QueryWrapper<>();
        QueryWrapper<UserBean> userName = wrapper.eq("userName", "0000");
        UserBean userBean = userMapper.selectOne(userName);

        if (userBean == null){
            System.out.println("是Null");
        }
        System.out.println(userBean);
    }
}

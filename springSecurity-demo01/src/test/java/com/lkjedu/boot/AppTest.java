package com.lkjedu.boot;



import com.lkjedu.boot.beans.UserBean;
import com.lkjedu.boot.mappers.UserMapper;
import org.junit.jupiter.api.Test;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Unit test for simple App.
 */
@SpringBootTest
@MapperScan("com.lkjedu.boot.mappers")
public class AppTest {
    @Autowired
    private UserMapper userMapper;
    /**
     * Rigorous Test :-)
     */
    @Test
    public void shouldAnswerWithTrue() {
        UserBean admin = userMapper.findById("admin");
        System.out.println(admin);
    }
}

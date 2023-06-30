package com.lkjedu.boot;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@MapperScan("com.lkjedu.boot.mapper")
@SpringBootApplication
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)//启用注解
public class ApplicationToken {
    public static void main(String[] args) {
        SpringApplication.run(ApplicationToken.class,args);
    }
}

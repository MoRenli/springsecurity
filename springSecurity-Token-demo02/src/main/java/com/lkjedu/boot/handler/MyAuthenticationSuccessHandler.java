package com.lkjedu.boot.handler;

import com.lkjedu.boot.domain.LoginUser;
import com.lkjedu.boot.service.impl.UserDetailServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private String url;
    @Autowired
    private UserDetailServiceImpl user;

    public MyAuthenticationSuccessHandler(String url) {
        this.url = url;
    }

    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.sendRedirect(url);
        //getPrincipal() 这个方法其实就是获取我们的User（SpringSecurity里面的User）
    }
}

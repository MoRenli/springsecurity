package com.lkjedu.boot.handler;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
    private String failUrl;

    public MyAuthenticationFailureHandler(String failUrl) {
        this.failUrl = failUrl;
    }


    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        request.setAttribute("SPRING_SECURITY_LAST_EXCEPTION", exception);
        response.sendRedirect(failUrl);
    }
}

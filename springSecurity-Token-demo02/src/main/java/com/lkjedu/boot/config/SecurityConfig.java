package com.lkjedu.boot.config;

import com.lkjedu.boot.handler.MyAuthenticationFailureHandler;
import com.lkjedu.boot.handler.MyAuthenticationSuccessHandler;
import com.lkjedu.boot.service.impl.UserDetailServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailServiceImpl userDetailService;
    @Autowired
    private DataSource dataSource;
    @Autowired
    private PersistentTokenRepository persistentTokenRepository;

    /*
    AuthenticationManagerBuilder，指定了自定义的UserDetailsService实现类来获取用户详细信息，
    并使用BCryptPasswordEncoder作为密码编码器进行密码加密。
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailService).passwordEncoder(bCryptPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //请求授权
        http.authorizeRequests()
                .antMatchers("/static/error.html").permitAll()
                .antMatchers("/static/main.html").permitAll()//放行某个接口这里mian.html不需要被认证
//                .antMatchers("/static/VIP.html").hasAnyAuthority("admin")//权限认证
//                .antMatchers("/static/VIP.html").hasRole("aaa")
                .anyRequest().authenticated();//任何请求都需要拦截

        //设置表达提交规则
        http.formLogin()
                .loginProcessingUrl("/login")//当发现表单的URL时认为是登录，必须和表单提交的地址一样，去执行UserDetailServiceImpl
                .loginPage("/static/main.html")//自定义登录页面
                .successForwardUrl("/toIndex")//登录成功之后跳转的页面接口
                //successHandler 不能和我们的 successForwardUrl 共存
//                .successHandler(new MyAuthenticationSuccessHandler("http://www.baidu.com"))
//                .failureForwardUrl("/toError");//登录失败后跳转页面
                .failureHandler(new MyAuthenticationFailureHandler("/static/error.html"));


        //实现记住我功能
        //注意：我们rememberMe()的默认失效时间其实是两周时间
        http.rememberMe()
                .tokenValiditySeconds(60)//设置失效时间，单位秒
//                .rememberMeParameter("设置我们的登录标单复选框的name属性值")
                .userDetailsService(userDetailService)//自定义登录逻辑
                .tokenRepository(persistentTokenRepository);//持久层对象

        //退出登录
        http.logout()
//                .logoutUrl("设置推出登录的URL")
                .logoutSuccessUrl("/static/main.html");//指定推出成功后登录页面
//                .logoutSuccessHandler()//这个也可以自定义我们自己的推出登录逻辑
        //关闭csrf()
        http.csrf().disable();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
       return new BCryptPasswordEncoder();
    }
    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();
        //注入数据源
        repository.setDataSource(dataSource);
        //自动创建表，第一次启动时需要。
//        repository.setCreateTableOnStartup(true);
        return  repository;
    }
}

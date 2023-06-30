package com.lkjedu.boot.beans;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

@Data
@TableName("t_user")
public class UserBean {
    private Integer id;
    private String userName;
    private String password;
    private String trueName;
}

package com.ho2ast.jwt.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter2 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        System.out.println("filter2");
        filterChain.doFilter(servletRequest, servletResponse);
    }
}

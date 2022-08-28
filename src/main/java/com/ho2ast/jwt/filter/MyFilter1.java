package com.ho2ast.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        // 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다.
        // 요청할 때 마다 header에 Authorization에 value값 전달
        // 그때 토큰이 정확한 토큰인지 검증하기만 하면 된다.
        if (req.getMethod().equals("POST")) {
            String authType = req.getAuthType();
            String header = req.getHeader("Authorization");
            System.out.println("header = " + header);
            System.out.println("authType = " + authType);

            if (header.equals("Bearer cos")) {
                filterChain.doFilter(servletRequest, servletResponse);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }
    }
}

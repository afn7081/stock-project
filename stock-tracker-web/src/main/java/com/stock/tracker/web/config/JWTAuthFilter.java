package com.stock.tracker.web.config;

import com.stock.tracker.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
@RequiredArgsConstructor
public class JWTAuthFilter extends OncePerRequestFilter {

    @Autowired
    JwtUtil jwtUtil;
    private final UserRepository userRepository;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authHeader=request.getHeader(AUTHORIZATION);
        final String userName;
        final String jwtToken;

        if (authHeader==null||!authHeader.contains("Bearer")){
            filterChain.doFilter(request,response);
            return;
        }
        jwtToken=authHeader.substring(7);
        userName=jwtUtil.extractUsername(jwtToken);
        if(userName!=null && SecurityContextHolder.getContext().getAuthentication()==null){

            UserDetails userDetails=userRepository.findByUsername(userName);


            if (jwtUtil.validateToken(jwtToken,userDetails)){

                UsernamePasswordAuthenticationToken authToken=
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }


        }

        filterChain.doFilter(request,response);

    }
}

package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.security1.config.oauth.PrincipalOauth2UserService;

import lombok.RequiredArgsConstructor;

/**
 * 1. 코드받기(인증) 2. 엑세스 토큰,
 * 3. 사용자 프로필 정보를 가져옴 4. 그 정보를 토대로 회원가입을 자동으로 진행
 */


@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터 체인에 등록
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) // secured 어노테이션 활성화,
// preAuthorize, PostAuthorize 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final PrincipalOauth2UserService principalOauth2UserService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
				.antMatchers("/user/**").authenticated() //인증만 되면 들어갈 수 있는 주소
				.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
				.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll() // 다른 요청들 모든 사용자가 접근 가능
				.and()
				.formLogin()
				.loginPage("/login-form") // login 페이지로 이동
				.loginProcessingUrl("/login")
				.defaultSuccessUrl("/")  // /login 주소가 호출이 되면 시큐리티가 낚아채서 로그인을 진행해준다
				.and()
				.oauth2Login()
				.loginPage("/loginForm")
				.userInfoEndpoint()
				.userService(principalOauth2UserService);// 구글 로그인이 완료된 뒤의 후처리가 필요함. Tip. 코드 X, (엑세스 토큰 + 사용자 프로필 정보를 다 받는다)

	}

}

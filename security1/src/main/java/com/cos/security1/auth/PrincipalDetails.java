package com.cos.security1.auth;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.cos.security1.model.User;

import lombok.RequiredArgsConstructor;

/**
 * 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
 * 로그인을 진행이 완료가 되면 시큐리티 session 을 만들어준다. (Security ContextHolder)
 * 오브젝트 -> Authentication 타입 객체
 * Authentication 안에 User정보가 있어야됨
 * User오브젝트 타입 -> UserDetails 타입 객체
 *
 * Security Session -> Authentication -> UserDetails(PrincipalDetails)
 */


@RequiredArgsConstructor
public class PrincipalDetails implements UserDetails {

	private final User user;

	// 해당 User 의 권한을 리턴
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collect = new ArrayList<>();
		collect.add((GrantedAuthority) user::getRole);
		return collect;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true; // 이계정 만료됐는지? 아니오
	}

	@Override
	public boolean isAccountNonLocked() {
		return true; // 계정이 잠겼는지? 아니오
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true; // 계정의 비밀번호가 기간이 지났는지 ? 아니오
	}

	@Override
	public boolean isEnabled() {

		// 1년간 미접속시 휴먼 계정 처리
		// 현재시간 -> 로긴 시간 -> 1년 초과하면 return false;

		return true; // 계정이 활성화 되었는지? 아니오
	}
}

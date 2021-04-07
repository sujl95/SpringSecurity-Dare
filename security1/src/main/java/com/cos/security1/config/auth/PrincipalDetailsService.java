package com.cos.security1.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

// 시큐리티 설정에서 loginProcessingUrl("/login");
// /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC되어 있는 loadUserByUsername 함수가 실행
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
	
	private final UserRepository userRepository;

	// 시큐리티 session(내부 Authentication(내부 UserDetails))

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// 주의 프론트에서 name="username"  이렇게 넘겨야 매칭된다 name="username2" 로 하게 되면 되지 않는다
		User userEntity = userRepository.findByUsername(username);
		if (ObjectUtils.isEmpty(userEntity)) {
			return null;
		}
		return new PrincipalDetails(userEntity);
	}
}

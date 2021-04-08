package com.cos.security1.config.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FaceBookInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

	private final UserRepository userRepository;

	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	// 구글로 부터 받은 userRequest 데이터에 대한 후처리되는 함수
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		// 구글 로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인 완료 -> code를 리턴(OAuth- Client라이브러리) -> AccessToken 요청
		// userRequest 정보 -> loadUser 함수 호출 -> 회원 프로필
		OAuth2User oAuth2User = super.loadUser(userRequest);
		System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());

		OAuth2UserInfo oAuth2UserInfo = null;
		if ("google".equals(userRequest.getClientRegistration().getRegistrationId())) {
			System.out.println("구글 로그인 요청");
			oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
		} else if ("facebook".equals(userRequest.getClientRegistration().getRegistrationId())) {
			System.out.println("페이스북 로그인 요청");
			oAuth2UserInfo = new FaceBookInfo(oAuth2User.getAttributes());
		} else {
			System.out.println("구글 로그인 , 페이스북 로그인만 됩니다");
		}

		String provider = oAuth2UserInfo.getProvider(); // google
		String providerId =  oAuth2UserInfo.getProviderId();
		String username = provider + "_" + providerId;
		String password = bCryptPasswordEncoder.encode("TheWing");
		String email =  oAuth2UserInfo.getEmail();
		String role = "ROLE_USER";

		User userEntity = userRepository.findByUsername(username);
		if (ObjectUtils.isEmpty(userEntity)) {
			userEntity = User.builder()
					.username(username)
					.password(password)
					.email(email)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			userRepository.save(userEntity);
		}

		return new PrincipalDetails(userEntity, oAuth2User.getAttributes()); // Authentication 객체에 들어간다
	}
}

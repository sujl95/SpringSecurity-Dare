package com.cos.security1.config.oauth.provider;

import java.util.Map;

import lombok.RequiredArgsConstructor;

public class KakaoInfo implements OAuth2UserInfo {
	private final Map<String, Object> attributes; // oauth2User.getAttributes();
	private final Map<String, Object> kakaoAccount;
	private final Map<String, Object> profile;

	public KakaoInfo(Map<String, Object> attributes) {
		this.attributes = attributes;
		kakaoAccount = (Map) attributes.get("kakao_account");
		profile =(Map) kakaoAccount.get("profile");
	}

	@Override
	public String getProviderId() {
		return String.valueOf(attributes.get("id"));
	}

	@Override
	public String getProvider() {
		return "kakao";
	}

	@Override
	public String getEmail() {
		return (String) kakaoAccount.get("email");
	}

	@Override
	public String getName() {
		return (String) profile.get("nickname");
	}
}

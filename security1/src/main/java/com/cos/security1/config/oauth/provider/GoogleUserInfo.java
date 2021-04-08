package com.cos.security1.config.oauth.provider;

import java.util.Map;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class GoogleUserInfo implements OAuth2UserInfo{

	private final Map<String, Object> attributes; // oauth2User.getAttributes();

	@Override
	public String getProviderId() {
		return (String) attributes.get("sub");
	}

	@Override
	public String getProvider() {
		return "google";
	}

	@Override
	public String getEmail() {
		return (String) attributes.get("email");
	}

	@Override
	public String getName() {
		return (String) attributes.get("name");
	}
}

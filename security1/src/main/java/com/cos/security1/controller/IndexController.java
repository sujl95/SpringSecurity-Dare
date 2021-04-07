package com.cos.security1.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class IndexController {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping("/test/login")
	@ResponseBody
	public String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) { // @AuthenticationPrincipal 로 세션 정보에 접근이 가능
		System.out.println("/test/login-----------");
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("principalDetails.getUsername() = " + principalDetails.getUsername());
		System.out.println("principalDetails.getAuthorities() = " + principalDetails.getAuthorities());
		System.out.println();
		System.out.println("userDetails.getUsername() = " + userDetails.getUsername());
		return "세션 정보 확인하기";
	}

	@GetMapping("/test/oauth/login")
	@ResponseBody
	public String testOAuthLogin(Authentication authentication, @AuthenticationPrincipal OAuth2User oAuth2User) {
		System.out.println("/test/OAuth/login-----------");
		OAuth2User principalDetails = (OAuth2User) authentication.getPrincipal();
		System.out.println("principalDetails.getAuthorities() = " + principalDetails.getAuthorities());

		System.out.println("oAuth2User.getAttributes() = " + oAuth2User.getAttributes());
		System.out.println("oAuth2User.getAuthorities() = " + oAuth2User.getAuthorities());
		
		return "OAuth 세션 정보 확인하기";
	}



	@GetMapping({"/",""})
	public String index() {

		return "index";
	}

	@GetMapping("/user")
	@ResponseBody
	public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("principalDetails.getUsername() = " + principalDetails.getUsername());
		return "user";
	}

	@GetMapping("/admin")
	@ResponseBody
	public String admin() {
		return "admin";
	}

	@GetMapping("/manager")
	@ResponseBody
	public String manager() {
		return "manager";
	}

	@GetMapping("/login-form")
	public String login() {
		return "loginForm";
	}

	@PostMapping("/join")
	public String join(User user) {
		System.out.println("user = " + user);
		user.setRole("ROLE_USER");
		String rawPassword = user.getPassword();
		String encodePassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encodePassword);
		userRepository.save(user);
		return "redirect:/login-form";
	}

	@GetMapping("/join-form")
	public String joinForm() {
		return "joinForm";
	}

	@GetMapping("/info")
	@Secured("ROLE_ADMIN")
	@ResponseBody
	public String info() {
		return "개인정보";
	}

	@GetMapping("/data")
	// @PreAuthorize("USER_ROLE") //먹히지않음
	@PreAuthorize("hasRole('ROLE_MANAGE') or hasRole('ROLE_ADMIN')")
	@ResponseBody
	public String data() {
		return "데이터정보";
	}
}

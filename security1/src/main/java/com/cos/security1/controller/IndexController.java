package com.cos.security1.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class IndexController {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping({"/",""})
	public String index() {

		return "index";
	}

	@GetMapping("/user")
	@ResponseBody
	public String user() {
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

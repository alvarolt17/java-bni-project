package com.bni.bni.service;

import com.bni.bni.entity.User;
import com.bni.bni.repository.UserRepository;
import com.bni.bni.util.JwtUtil;
import org.slf4j.Logger;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.Optional;

@Service
public class AuthService {
    private final Logger logger = org.slf4j.LoggerFactory.getLogger(AuthService.class);
    private final PasswordEncoder encoder;
    private final JwtUtil jwtUtil;
    private final UserRepository repo;

    public AuthService(PasswordEncoder encoder, JwtUtil jwtUtil, UserRepository repo) {
        this.encoder = encoder;
        this.jwtUtil = jwtUtil;
        this.repo = repo;
    }

    public String register(String username, String password, String email) {
        if (repo.existsByUsername(username)) {
            logger.warn("PERCOBAAN REGISTRASI GAGAL - Username sudah terdaftar: {}", username);
            return "Username already exists";
        }

        User user = new User();
        user.setUsername(username);
        user.setEmailAddress(email);
        user.setPassword(encoder.encode(password));
        user.setIsActive(true);
        user.setCreatedAt(OffsetDateTime.now());
        user.setUpdatedAt(OffsetDateTime.now());

        repo.save(user);

        logger.info("REGISTRASI BERHASIL UNTUK USER: {}", username);
        return "Registered successfully";
    }

    public String login(String username, String password) {
        Optional<User> user = repo.findByUsername(username);
        if (user.isPresent() && encoder.matches(password, user.get().getPassword())) {
            logger.info("LOGIN BERHASIL DENGAN USERNAME: {}", username);
            return jwtUtil.generateToken(username, password);
        }

        logger.warn("LOGIN GAGAL - Username atau password salah: {}", username);
        return null;
    }
}
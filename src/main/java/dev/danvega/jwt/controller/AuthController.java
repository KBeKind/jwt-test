package dev.danvega.jwt.controller;

import dev.danvega.jwt.model.LoginRequest;
import dev.danvega.jwt.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin
public class AuthController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class);

    private final TokenService tokenService;
    private final AuthenticationManager authenticationManager;

    public AuthController(TokenService tokenService, AuthenticationManager authenticationManager) {
        this.tokenService = tokenService;
        this.authenticationManager = authenticationManager;
    }

    //@PostMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    // IM ADDIN COMMENTS TO TEST MERGING SOMETHING

    @PostMapping("/token")
    public ResponseEntity<?> token(@RequestBody LoginRequest userLogin) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userLogin.username(), userLogin.password())
            );
            String jwt = tokenService.generateToken(authentication);

            LOG.info("Generated JWT: {}", jwt);

            return ResponseEntity.ok(jwt);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authentication failed");
        }
    }




}

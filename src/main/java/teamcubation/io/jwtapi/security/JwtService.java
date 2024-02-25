package teamcubation.io.jwtapi.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.stream.Collectors;

@Service
public class JwtService {
  private final JwtEncoder encoder;

  public JwtService(JwtEncoder encoder) {
    this.encoder = encoder;
  }

  public String generateToken(Authentication authentication) {
    Instant now = Instant.now(); // inicio da vida util do token
    long expiry = 36000L; //  expira em 1h

    String scope = authentication
        .getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors
            .joining(" "));  //  montando as authorities (papeis) da aplicação

    JwtClaimsSet claims = JwtClaimsSet.builder() // claims são as propriedades do token
        .issuer("spring-security-jwt")  // é o identity provider
        .issuedAt(now)
        .expiresAt(now.plusSeconds(expiry)) // data de inspiração
        .subject(authentication.getName()) // dono do token
        .claim("scope", scope)
        .build();

    return encoder.encode(
        JwtEncoderParameters.from(claims))
        .getTokenValue();
  }

}

package com.jwt.demoJwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
 import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    private final String SECRET_KEY = "90931aa57528a950d75b961c47da45522b083c2401ddbd9a8b582ad8559207bc";

    public <T> T extractClaim(String token, Function<Claims,T> resolver){
        Claims cl=getClaimsFromToken(token  );
        return resolver.apply(cl);
    }

    public boolean isvalid(String token,User user){
        String name=extractUsername(token);
        return user.getName().equals(name) && !isTokenExpired(token);

    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
          return extractClaim(token,Claims::getExpiration);
    }


    public String extractUsername(String token){
        return extractClaim  (token, Claims::getSubject);
    }

    public String generateToken(User user) {
        String token= Jwts.builder().subject(user.getName()).issuedAt(new Date(System.currentTimeMillis())).expiration(new Date(System.currentTimeMillis()+24*60*60*1000))
                .signWith(getSignKey()).compact();
        return token;

    }

    private Claims getClaimsFromToken(String token) {
        return Jwts.parser().verifyWith(getSignKey()).build().parseClaimsJws(token).getPayload()   ;
    }

    private SecretKey getSignKey()  {
        byte key[]= Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(key);
    }
}

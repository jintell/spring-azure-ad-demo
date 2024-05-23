package com.jade.platform.config.provider;

import com.jade.platform.config.converter.CombinedClaimConverter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

/**
 * @Author: Josiah Adetayo
 * @Email: josleke@gmail.com, josiah.adetayo@meld-tech.com
 * @Date: 5/23/24
 */
@Component
public class AdJwtAuthenticationProvider implements ReactiveAuthenticationManager {
    private final Log log = LogFactory.getLog(this.getClass());

    private final JwtDecoder jwtDecoder;
    private Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = new JwtAuthenticationConverter();

    public AdJwtAuthenticationProvider(JwtDecoder jwtDecoder, CombinedClaimConverter converter) {
        this.jwtDecoder = jwtDecoder;
        this.setJwtAuthenticationConverter(converter);
    }
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken)authentication;
        Jwt jwt = this.getJwt(bearer);
        AbstractAuthenticationToken token = this.jwtAuthenticationConverter.convert(jwt);
        assert token != null;
        token.setDetails(bearer.getDetails());

        this.log.debug("Authenticated token" +jwt);
        return Mono.just(token);
    }

    private Jwt getJwt(BearerTokenAuthenticationToken bearer) {
        try {
            return this.jwtDecoder.decode(bearer.getToken());
        } catch (BadJwtException var3) {
            this.log.debug("Failed to authenticate since the JWT was invalid");
            throw new InvalidBearerTokenException(var3.getMessage(), var3);
        } catch (JwtException var4) {
            throw new AuthenticationServiceException(var4.getMessage(), var4);
        }
    }

    public void setJwtAuthenticationConverter(Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter) {
        Assert.notNull(jwtAuthenticationConverter, "jwtAuthenticationConverter cannot be null");
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
    }

}

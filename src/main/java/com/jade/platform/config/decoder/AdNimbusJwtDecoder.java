package com.jade.platform.config.decoder;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.util.StringUtils;

import java.text.ParseException;
import java.util.*;
import java.util.stream.Stream;

/**
 * @Author: Josiah Adetayo
 * @Email: josleke@gmail.com, josiah.adetayo@meld-tech.com
 * @Date: 5/23/24
 */
public class AdNimbusJwtDecoder implements JwtDecoder {

    private final Log log = LogFactory.getLog(this.getClass());

    @Value("${spring.azure-ad.issuerUri:}")
    private String issuerUri;

    @Value("${spring.azure-ad.audiences:}")
    private String audiences;

    private static final String ERROR_MSG = "An error occurred while attempting to decode the Jwt: %s";
    private final Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
    private final OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();
    @Override
    public Jwt decode(String token) throws JwtException {
        JWT jwt = this.parse(token);
        if (jwt instanceof PlainJWT) {
            this.log.trace("Failed to decode unsigned token");
            throw new BadJwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
        } else {
            Jwt createdJwt = this.createJwt(token, jwt);
            return this.validateJwt(createdJwt);
        }
    }

    private JWT parse(String token) {
        try {
            return JWTParser.parse(token);
        } catch (Exception var3) {
            this.log.trace("Failed to parse token", var3);
            if (var3 instanceof ParseException) {
                throw new BadJwtException(String.format(ERROR_MSG, "Malformed token"), var3);
            } else {
                throw new BadJwtException(String.format(ERROR_MSG, var3.getMessage()), var3);
            }
        }
    }

    private Jwt createJwt(String token, JWT parsedJwt) {
        try {
            JWTClaimsSet jwtClaimsSet = parsedJwt.getJWTClaimsSet();
            Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
            Map<String, Object> claims = this.claimSetConverter.convert(jwtClaimsSet.getClaims());

            assert claims != null;

            if(Objects.nonNull(issuerUri) && !issuerUri.isEmpty() && !issuerUri.equals(claims.get("iss")))
                throw new JOSEException("Invalid issuer");

            if(Objects.nonNull(audiences) && !audiences.isEmpty()) {
                List<String> audienceList = getAudiences(claims.getOrDefault("aud", "[]").toString());
                if(audienceList.stream().noneMatch(aud -> aud.equals(audiences)))
                    throw new JOSEException("Invalid audience");
            }

            return Jwt.withTokenValue(token).headers(h ->
                h.putAll(headers)
            ).claims((c) ->
                c.putAll(claims)
            ).build();
        }
        catch (JOSEException var7) {
            this.log.trace("Failed to process JWT", var7);
            throw new JwtException(String.format(ERROR_MSG, var7.getMessage()));
        }
        catch (Exception var8) {
            this.log.trace("Failed to process JWT", var8);
            if (var8.getCause() instanceof ParseException) {
                throw new BadJwtException(String.format(ERROR_MSG, "Malformed payload"), var8);
            } else {
                throw new BadJwtException(String.format(ERROR_MSG, var8.getMessage()), var8);
            }
        }
    }

    private Jwt validateJwt(Jwt jwt) {
        OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);
        if (result.hasErrors()) {
            Collection<OAuth2Error> errors = result.getErrors();
            String validationErrorString = this.getJwtValidationExceptionMessage(errors);
            throw new JwtValidationException(validationErrorString, errors);
        } else {
            return jwt;
        }
    }

    private String getJwtValidationExceptionMessage(Collection<OAuth2Error> errors) {
        Iterator var2 = errors.iterator();

        OAuth2Error oAuth2Error;
        do {
            if (!var2.hasNext()) {
                return "Unable to validate Jwt";
            }

            oAuth2Error = (OAuth2Error)var2.next();
        } while(!StringUtils.hasLength(oAuth2Error.getDescription()));

        return String.format(ERROR_MSG, oAuth2Error.getDescription());
    }

    private List<String> getAudiences(String audienceFromClaim) {
        String OPEN_BRACKET = "[";
        String CLOSE_BRACKET = "]";
        String REPLACEMENT = "";

        String claimAudiences = audienceFromClaim.
                replace(OPEN_BRACKET, REPLACEMENT)
                .replace(CLOSE_BRACKET, REPLACEMENT);

        if(claimAudiences.contains(",")) return Stream.of(claimAudiences.split(",")).toList();
        else if(claimAudiences.contains(" ")) return Stream.of(claimAudiences.split(" ")).toList();
        else if(!claimAudiences.trim().isEmpty()) return Collections.singletonList(claimAudiences);
        return new ArrayList<>();
    }

}

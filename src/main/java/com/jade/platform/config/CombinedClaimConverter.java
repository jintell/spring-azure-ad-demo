package com.jade.platform.config;

import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.util.annotation.NonNull;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @Author: Josiah Adetayo
 * @Email: josleke@gmail.com, josiah.adetayo@meld-tech.com
 * @Date: 5/12/24
 */
@Component
@RequiredArgsConstructor
public class CombinedClaimConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {
    // The combined converter internally fuses the outputs of two converters.
    // One component is the default converter (extracting scp/scope claim information).
    // So we create one instance of this off-the-shelf convert for later use.
    private final JwtGrantedAuthoritiesConverter defaultGrantedAuthoritiesConverter
            = new JwtGrantedAuthoritiesConverter();

    /**
     * This method provides the second component of our custom converter. It is a manual
     * implementation that searches the jwt for a custom "roles" claim. If found, all entries
     * prefixed with "ROLE_", removes the prefix leaving the role and returned as list of authorities.
     *
     * @param jwt as the json web token to analyze for "role" claim entries.
     * @return collection of granted authorities extracted from the jwt.
     */
    private static Collection<? extends GrantedAuthority> extractResourceRoles(final Jwt jwt) {
        // <- specify here whatever additional jwt claim you wish to convert to authority
        ArrayList<String> resourceAccess = jwt.getClaim("roles");
        if (resourceAccess != null) {
            // Convert every entry in value list of "role" claim to an Authority - new SimpleGrantedAuthority("ROLE_" + x))
            return resourceAccess.stream()
                    .map(role -> (role.contains("ROLE_")? role.replace("ROLE_", "") : role))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toSet());
        }
        // Fallback: return empty list in case the jwt has no "role" claim.
        return Collections.emptySet();
    }

    /**
     * This is the main converter method to override. In essence here we provide a custom
     * implementation that concatenates the authority lists generated from two respective converters.
     * One is the off-the-shelf default converter that operates on the "scp"/"scope" claim. The other
     * is the converter for our custom claim.
     *
     * @param source as the json web token to inspect for claims
     * @return list of authorities extracted from token, wrapped up in AbstractAuthenticationToken
     * object.
     */
    @Override
    public Mono<AbstractAuthenticationToken> convert(@NonNull Jwt source) {
        try {
            Collection<GrantedAuthority> authorities =
                    Stream.concat(defaultGrantedAuthoritiesConverter.convert(source).stream()
                                    .map(scope -> new SimpleGrantedAuthority( (scope.getAuthority().contains("SCOPE_")?
                                            scope.getAuthority().replace("SCOPE_", "") :
                                            scope.getAuthority()) )),
                            extractResourceRoles(source).stream()).collect(Collectors.toSet());
            return Mono.just(new JwtAuthenticationToken(source, authorities));
        }catch (NullPointerException exception) {
            return Mono.error(exception.getCause());
        }
    }

}

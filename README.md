# Spring WebFlux Reactive Resource Server with RBAC and token from Azure AD

This demo explains how to validate Azure AD JWT token based RBAC implementation for a Spring WebFlux reactive app.

Spring provides a maven spring boot dependency, `spring-boot-starter-oauth2-resource-server` for authentication and 
protecting resource APis.

This demo capitalizes on the spring reactive `spring-boot-starter-webflux` dependency along with 
`spring-security-oauth2-resource-server` and `spring-security-oauth2-jose` to implement a reactive spring OAuth2.0 
resource server validate Azure AD tokens and other OAuth2.0 Provider's token.

### Project Setup Requirement
1. Java 17 or higher
2. Gradle 8.7 or higher

## Spring Resource Server Setup

### Maven Dependencies

Add the below maven dependencies to your project:

```
    implementation 'org.springframework.boot:spring-boot-starter-webflux'
    implementation 'org.springframework.security:spring-security-oauth2-jose'
    implementation 'org.springframework.boot:spring-boot-starter-oauth2-resource-server'
```

### Configure resource server to validate and use Azure AD provider

In `application.yml`, initialize spring security resource server to use Azure AD as the authorization server by setting
`spring.security.oauth2.resourceserver.jwt.issuer-uri` to the issuer URI of your app.

```yaml
spring:
  application:
    name: SpringApplicationAAD
  azure-ad:
    issuerUri: ${ISSUER_URI}
    audiences: ${AUDIENCES}
```
* Note: If the `spring.azure-ad.issuerUri` and/or `spring.azure-ad.audiences` are not present in the properties file, 
it's assumed that further verification against the issuer and audience are not needed.

To find your issuer URI,
- Use the `iss` claim in your JWT token
- Build it yourself: `https://sts.windows.net/<your-tenant-id>/` For Azure AD version 1.0
- Build it yourself: `https://login.microsoftonline.com/<your-tenant-id>/v2.0` For Azure AD version 2.0

### Enable Spring WebFlux Security

- Use `@EnableWebFluxSecurity` to enable Spring WebFlux reactive security
- Optionally, use `@EnableReactiveMethodSecurity` to enable method level security checks, including pre/post authorize annotations

At this point, your application is fully secured by Spring Resource Server based RBAC. However, this is incomplete. 
With the above configurations, Spring only checks for the `iss` claim i.e., the JWT token's issuer and `exp` claim i.e., the JWT token's expiry.

This is by design, as Spring allows plugging in multiple auth providers and implementations.

### Customizing Security Checks

1. Create a custom `ReactiveAuthenticationManager` and then implement the authenticate method.
2. Create a custom `ServerSecurityContextRepository` then implement the load method.
3. Create a custom `JwtDecoder` found in the spring security oauth2 jwt package and implement the decode method
4. Inject `JwtDecoder` into the `ReactiveAuthenticationManager`, Inject the `ReactiveAuthenticationManager` into the `ServerSecurityContextRepository`

#### Create A bean of your Custom JwtDecoder

Create your custom `AdNimbusJwtDecoder` implementation and expose as a bean

```java
    @Bean
    public JwtDecoder jwtDecoder() {
        return new AdNimbusJwtDecoder();
    }
```

### Enable Spring WebFlux Security and configure

- Add the `@EnableWebFluxSecurity` to enable Spring WebFlux reactive security
- Add the `@EnableReactiveMethodSecurity` to enable method level security checks, including pre/post authorize annotations
- Inject the Authentication Manager (Custom Provider)
- Inject the Security Context Repository (Custom)

Then, configure the `springWebFilterChain` and expose it as a bean:

```java
@Bean
public SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
    http
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .authenticationManager(provider)
            .securityContextRepository(contextRepository)
            .authorizeExchange(authorizeExchangeSpec ->
                    authorizeExchangeSpec
                            .pathMatchers(AUTH_WHITELIST)
                            .permitAll()
                            .anyExchange()
                            .authenticated()
            );
    return http.build();
}
```

Please Note:
If our application will need these roles or groups,  and intends to implement method level authorization, 
typically via `@PreAuthorize("hasRole('<your role>')"`, supply your custom authority extractor `CombinedClaimConverter` 
like below:

```java
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
```

Every request with a JWT token would be converted into an `AuthenticatedPrincipal` and can be used in every layer of 
your application to perform the needed pre-authorization.

See a sample method below that checks if the incoming request's has the role `readUser` as part of the `roles` claim.

```java
@GetMapping("/api/v1/demo/user")
@PreAuthorize("hasAuthority('readUser')")
public Mono<String> user() {
    return Mono.just("User: " + UUID.randomUUID());
}
```

### Reference Documentation

For further reference, please consider the following sections:

* [Official Gradle documentation](https://docs.gradle.org)
* [Spring Boot Gradle Plugin Reference Guide](https://docs.spring.io/spring-boot/docs/3.2.5/gradle-plugin/reference/html/)
* [Create an OCI image](https://docs.spring.io/spring-boot/docs/3.2.5/gradle-plugin/reference/html/#build-image)
* [Azure Active Directory](https://microsoft.github.io/spring-cloud-azure/current/reference/html/index.html#spring-security-with-azure-active-directory)
* [OAuth2 Resource Server](https://docs.spring.io/spring-boot/docs/3.2.5/reference/htmlsingle/index.html#web.security.oauth2.server)
* [Spring Reactive Web](https://docs.spring.io/spring-boot/docs/3.2.5/reference/htmlsingle/index.html#web.reactive)

### Guides

The following guides illustrate how to use some features concretely:

* [Building a Reactive RESTful Web Service](https://spring.io/guides/gs/reactive-rest-service/)

### Additional Links

These additional references should also help you:

* [Gradle Build Scans – insights for your project's build](https://scans.gradle.com#gradle)
* [Azure Active Directory Sample](https://aka.ms/spring/samples/latest/aad)


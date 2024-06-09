# Authentication in spring boot using spring security in JAVA

In this we are going to discuss how we can implement the jwt based authentication using spring security in spring boot.


##  **Terminologies**

  - - **Authentication** refers to the process of verifying the identity of a user, based on provided credentials. A common example is entering a username and a password when you log in to a website. You can think of it as an answer to the question _Who are you?_.
  - - **Authorization** refers to the process of determining if a user has proper permission to perform a particular action or read particular data, assuming that the user is successfully authenticated. You can think of it as an answer to the question _Can a user do/read this?_.
  - - **Principle** refers to the currently authenticated user.
  - - **Granted authority** refers to the permission of the authenticated user.
  - - **Role** refers to a group of permissions of the authenticated user.

#### **First of all we need to know what is Spring security and how it works ?**

Spring security is a cutomisable authentication and access control framework for java based spring application.

##### Key features
1. Authentication
2. Authorization
3. Password Management : - Storage of passwords and their encryption.
4. Session Management : Manages user sessions to prevent fixation and ensures secure session handling
5. Protection against 
	  - CSRF(Cross-Site Request Forgery) : - Protects against malicious actions performed by authenticated user without their consent.
	  - XSS( Cross site scripting): Helps prevent injection of malicious scripts.

### How Spring Security Works
 Configuration
Java Configuration : Uses Java-based configuration to set up security features. This is done by making a class and Annotatting it with `@EnableWebSecurity` annotation.


# Spring Security Architecture
 ![[spring-security-architecture.png]]

### Spring Security Filters Chain

When you add the Spring security framework to your application it automatically registers a filters chain that intercepts all incoming requests. This chain consists of various filters and each of them handles a particular use case 

> [!NOTE]
>   Spring Security filters are registered with the lowest order and are the first filters invoked 

## AuthenticationManager

`AuthenticationManager` is an interface that defines a single method , `authenticate(Authentication authentication)` , which is used to verify the credentials of a user and determine if they are valid.
You can think of `AuthenticationManager` as a coordinator where you can register multiple providers, and based on the request type, it will deliver an authentication request to the correct provider.

## AuthenticationProvider

It is an interface that defines a contract for authenticating a user based on the provided credentials. Multiple `AuthenticationProvider` instances can be configured to support different types of authentication mechanisms (e.g., username/password, OAuth, LDAP, etc.).

### Key Concepts of `AuthenticationProvider`

1. **Authentication**: The `AuthenticationProvider` processes an `Authentication` object, which contains the user's credentials.
2. **Authenticate Method**: It implements the `authenticate(Authentication authentication)` method to perform the authentication logic.
3. **Supports Method**: It implements the `supports(Class<?> authentication)` method to indicate whether the `AuthenticationProvider` can handle the given type of `Authentication`.

### How `AuthenticationProvider` Works

#### Authentication Flow

1. **Receive Authentication Request**: An `Authentication` object containing user credentials is passed to the `AuthenticationProvider`.
2. **Validate Credentials**: The `AuthenticationProvider` validates the credentials against a data source (e.g., a database, an LDAP server).
3. **Return Authenticated Object**: If the credentials are valid, it returns a fully populated `Authentication` object with user details and granted authorities.
4. **Handle Authentication Failure**: If the credentials are invalid, it either throws an `AuthenticationException` or returns `null` to let other `AuthenticationProvider` instances try to authenticate.


> [!NOTE] 
>Here we are using implementation of the `AuthenticationProvider` interface which is `DaoAuthenticationProvider` , which retrieves user details from a `UserDetailsService`

## UserDetailsService

`UserDetailsService` is described as a core interface that loads user-specific data in the Spring documentation
It contains a single method `loadUserByUsername` which accepts username as parameter and returns the ==User== identity object . Basically we create and implementation class of `UserDetailsService` in which we override the `loadUserByUsername` method.

#### **Now before moving to the configuration and all stuff here's a concise flow of Spring Security for JWT-based authentication:**

### 1. **User Authentication Request**

- **Login Request**: The user sends a POST request to the login endpoint (`/login`) with their credentials (username and password).
### 2. **AuthenticationManager**

- **AuthenticationManager**: This receives the authentication request and delegates it to the appropriate `AuthenticationProvider` which we configure.

```java
@Bean  
public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{  
return config.getAuthenticationManager();  
}
```
### 3. **AuthenticationProvider**

- **UserDetailsService**: The `AuthenticationProvider` uses `UserDetailsService` to load user details based on the username. And we provide this with a implementation of `UserDetailsService`
- **Credential Validation**: It compares the provided password with the one stored in the user details (typically using a `PasswordEncoder`).

```java
@Bean  
public AuthenticationProvider authenticationProvider(){  
DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();  
authenticationProvider.setUserDetailsService(userDetailsServiceImpl);  
authenticationProvider.setPasswordEncoder(passwordEncoder);  
return authenticationProvider;  
}
```
### 4.**JWT Token Generation**

- **Generate JWT**: Upon successful authentication, a JWT token is generated using a `JwtTokenUtil` (or similar utility class).
- **Return Token**: The JWT token is sent back to the client in the response.

### 5. **Subsequent Requests with JWT**

- **Client Request with JWT**: The client includes the JWT token in the `Authorization` header of subsequent requests (typically as `Bearer <token>`).
### 6. **JWT Authentication Filter**

- **JWT Authentication Filter**: A custom filter (`JwtAuthenticationFilter`) intercepts requests to extract and validate the JWT token.
- **Extract Token**: The filter extracts the JWT token from the `Authorization` header.
- **Validate Token**: It validates the token using the `JwtService` (Our service class containing Jwt Specific methods ) to check its integrity and expiration.
- **Load User Details**: If the token is valid, the filter loads user details from the `UserDetailsService`.
- After successfull validation A UsernamePasswordAuthenticationToken is generated to set it into the securityContext;
- **Create Authentication Object**: The filter creates an `Authentication` object with the user details.
- **Set in SecurityContext**: This `Authentication` object is set in the `SecurityContext` to indicate a successful authentication.

```java
@Component  
@AllArgsConstructor  
public class JwtAuthFilter extends OncePerRequestFilter  
{  
@Autowired  
private final JwtService jwtService;  
@Autowired  
private final UserDetailsServiceImpl userDetailsService;  
@Override  
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {  
String authHeader = request.getHeader("Authorization");  
String token = null;  
String username = null;  
if(authHeader!=null&&authHeader.startsWith("Bearer ")){  
token = authHeader.substring(7);  
username = jwtService.extractUsername(token);  
  
}  
if(username!=null&& SecurityContextHolder.getContext().getAuthentication()==null){  
UserDetails userDetails = userDetailsService.loadUserByUsername(username);  
if(jwtService.validToken(token,userDetails)){  
UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());  
authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));  
SecurityContextHolder.getContext().setAuthentication(authenticationToken);  
}  
}  
filterChain.doFilter(request,response);  
}  
}
```

## **Final Configuration**

 We are implementing a REST API and need stateless authentication with a JWT token; therefore, we need to set the following options:

- Enable [CORS](https://en.wikipedia.org/wiki/Cross-origin_resource_sharing) and disable [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery).
- Set session management to stateless.
- Set unauthorized requests exception handler.
- Set permissions on endpoints.
- Add JWT token filter.

```java
@Configuration  
@EnableMethodSecurity  
@Data  
public class SecurityConfig  // Configuration Class
{  
@Autowired  
private final PasswordEncoder passwordEncoder;
@Autowired  
private final UserDetailsServiceImpl userDetailsServiceImpl;  
  
@Autowired  // this will indicate to automatically inject method parameter dependency
@Bean   // method produces a bean to be managed by the Spring container.
public UserDetailsService userDetailsService(UserInfoRepository userInfoRepository,PasswordEncoder passwordEncoder){  
return new UserDetailsServiceImpl(userInfoRepository,passwordEncoder);  
}  
@Bean  
public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity,JwtAuthFilter jwtAuthFilter) throws Exception  
{  
return httpSecurity.csrf(AbstractHttpConfigurer::disable).cors(CorsConfigurer::disable)  
.authorizeHttpRequests  
(auth
->auth.requestMatchers("/auth/v1/login","/auth/v1/refreshToken","/auth/v1/signup") 
.permitAll()  
.anyRequest()  
.authenticated()  
)  
.sessionManagement(session
->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  
.httpBasic(Customizer.withDefaults())  
.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)  
.authenticationProvider(authenticationProvider())  
.build();  
}  
@Bean  // Creates bean for AuthenticationProvider
public AuthenticationProvider authenticationProvider(){  
DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();  
authenticationProvider.setUserDetailsService(userDetailsServiceImpl);  
authenticationProvider.setPasswordEncoder(passwordEncoder);  
return authenticationProvider;  
}  
  
@Bean  // Creates bean for the AuthenticationManager
public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception{  
return config.getAuthenticationManager();  
}  
}
```

> [!NOTE]
> We added the `JwtAuthFilter` before the Spring Security internal `UsernamePasswordAuthenticationFilter`. We’re doing this because we need access to the user identity at this point to perform authentication/authorization, and its extraction happens inside the JWT token filter based on the provided JWT token and a further UsernamePasswordAuthenticationToken is provided to ensure the request is authenticated.

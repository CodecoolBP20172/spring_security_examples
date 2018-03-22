@Slf4j
@ComponentAuthenticationProvid
public class JwtAuthenticationProvider extends AbstractUserDetailser {

    @Autowired
    private JwtTokenValidator jwtTokenValidator;

    @Autowired
    private StudentRepository studentRepository;

    @Override
    public boolean supports(Class<?> authentication) {
        return (JwtAuthenticationToken.class.isAssignableFrom(authentication));
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws JwtAuthenticationException {
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

        JwtAuthenticationToken jwtAuthenticationToken = (JwtAuthenticationToken) authentication;

        String token = jwtAuthenticationToken.getToken();

        String email = jwtTokenValidator.parseToken(token);

        if (email == null) {
            throw new JwtAuthenticationException("Invalid JWT token");
        }

        Student student = studentRepository.findByEmail(email);

        if(student == null){
            throw new JwtAuthenticationException("User not found for JWT token");
        }

        log.trace("Parsed user from request JWT: {}", student);

        return new AuthenticatedUser(
                email,
                token,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_STUDENT")));
    }

}

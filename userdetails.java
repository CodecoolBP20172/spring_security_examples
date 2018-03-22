@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private static final Logger log = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username).orElse(null);

        if (user == null) {
            String message = "Username not found: " + username;
            log.info(message);
            throw new UsernameNotFoundException(message);
        }


        List<GrantedAuthority> authorities = user.getRole().getPermissions()
                .stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.User(
                username,
                user.getPasswordDigest(),
                user.getEnabled(),
                true, //Account Not Expired
                true, //Credentials Not Expired
                true, //Account Not Locked
                authorities
        ) {
        };

    }
}

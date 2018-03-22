@Configuration
@EnableWebSecurity // needed somewhere in the app.
class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired
    private UserDetailsServiceImpl userDetailsService;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(new BCryptPasswordEncoder());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/**/*.{js,html}");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http

                .formLogin().loginProcessingUrl("/api/authenticate")
                .successHandler(authenticationSuccessHandler())
                .failureHandler(authenticationFailureHandler())
                .permitAll()

                .and()

                .logout().deleteCookies("remember-me")
                .logoutUrl("/api/logout")
                .logoutSuccessHandler(logoutSuccessHandler())
                .deleteCookies("JSESSIONID")
                .permitAll()

                .and()

                .authorizeRequests().antMatchers(HttpMethod.GET, "/api/users/me").permitAll()
                .and().authorizeRequests().antMatchers(HttpMethod.GET, "/api/version*").permitAll()

                .and().authorizeRequests().antMatchers("/api/users/getEmail/*").permitAll()
                .and().authorizeRequests().antMatchers("/api/users/forgotPassword/").permitAll()
                .and().authorizeRequests().antMatchers("/api/users/changePassword").hasAuthority("CHANGE_PASSWORD_PRIVILEGE")
                .and().authorizeRequests().antMatchers("/api/**").authenticated()
                .and().authorizeRequests().antMatchers("/").permitAll()
                .anyRequest().authenticated()
                .and()
                .rememberMe()
                .tokenValiditySeconds(86400)
                .and().csrf().disable()
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint());

        if ("true".equals(System.getProperty("httpsOnly"))) {
            log.info("launching the application in HTTPS-only mode");
            http.requiresChannel().anyRequest().requiresSecure();
        }
    }


    /**
     * Creates a custom authentication success handler.
     * It does redirect to '/api/users/username' after successful login.
     * Username is taken from the Authentication object.
     *
     * @return AuthenticationSuccessHandler
     */
    @Bean
    AuthenticationSuccessHandler authenticationSuccessHandler() {

        return new SimpleUrlAuthenticationSuccessHandler() {

            @Override
            public void onAuthenticationSuccess(HttpServletRequest request,
                                                HttpServletResponse response,
                                                Authentication authentication) throws IOException, ServletException {

                String targetUrl = "/api/users/me";

                if (response.isCommitted()) {
                    log.debug("Response has already been committed. Unable to redirect to {}", targetUrl);
                    return;
                }

                getRedirectStrategy().sendRedirect(request, response, targetUrl);
            }
        };
    }

    /**
     * Creates a custom AuthenticationFailureHandler
     * It returns custom errors with {@link HttpServletResponse#SC_UNAUTHORIZED} (401) HTTP Status.
     *
     * @return AuthenticationFailureHandler
     */
    @Bean
    AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> {
            if (exception instanceof DisabledException) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User account suspended");
            } else {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
            }
        };
    }

    @Bean
    LogoutSuccessHandler logoutSuccessHandler() {
        return (request, response, authentication) ->
                response.setStatus(HttpStatus.OK.value());
    }

    @Bean
    AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            log.trace("Pre-authenticated entry point called ({}). Rejecting access.", request.getRequestURI(), authException);
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            PrintWriter writer = response.getWriter();
            writer.println("HTTP Status 401 - " + authException.getMessage());
        };
    }
}
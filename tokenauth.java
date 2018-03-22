@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JwtAuthenticationProvider authenticationProvider;

    @Autowired
    private JwtCompanyAuthenticationProvider jwtCompanyAuthenticationProvider;

    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return new ProviderManager(Arrays.asList(jwtCompanyAuthenticationProvider, authenticationProvider));
    }

    @Bean
    public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {

        // match GET and POST under / for authentication.
        RequestMatcher getRequestMatcher = new AntPathRequestMatcher("/api/**", HttpMethod.GET.name(), false);
        RequestMatcher postRequestMatcher = new AntPathRequestMatcher("/api/**", HttpMethod.POST.name(), false);
        RequestMatcher deleteRequestMatcher = new AntPathRequestMatcher("/api/**", HttpMethod.DELETE.name(), false);
        RequestMatcher putRequestMatcher = new AntPathRequestMatcher("/api/**", HttpMethod.PUT.name(), false);


        // allow /api/login
        RequestMatcher notLogin = new NegatedRequestMatcher(
                new AntPathRequestMatcher("/api/login**")
        );

        // allow /api/login/callback
        RequestMatcher notCallback = new NegatedRequestMatcher(
                new AntPathRequestMatcher("/api/login/callback")
        );

        RequestMatcher orRequestMatcher = new OrRequestMatcher(getRequestMatcher, postRequestMatcher, deleteRequestMatcher, putRequestMatcher);

        RequestMatcher andRequestMatcher = new AndRequestMatcher(notCallback, notLogin, orRequestMatcher);

        JwtAuthenticationTokenFilter authenticationTokenFilter = new JwtAuthenticationTokenFilter(andRequestMatcher);
        authenticationTokenFilter.setAuthenticationManager(authenticationManager());
        authenticationTokenFilter.setAuthenticationSuccessHandler(jwtAuthenticationSuccessHandler());
        return authenticationTokenFilter;

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/**/*.{js,html}");
    }


    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        
        httpSecurity
                .csrf().disable()
                .logout().logoutUrl("/logout")

                .and()
                // errorHandler if authentication/authorisation fails
                .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint());

        // Custom JWT based security filter
        httpSecurity
                .addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

    }

    @Bean
    public AuthenticationEntryPoint jwtAuthenticationEntryPoint(){
        return (httpServletRequest, httpServletResponse, e) ->
                httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }

    @Bean
    public AuthenticationSuccessHandler jwtAuthenticationSuccessHandler(){
        return (httpServletRequest, httpServletResponse, authentication) -> {
            // don't do anything.
        };
    }
}

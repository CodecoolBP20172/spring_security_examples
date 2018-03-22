@Slf4j
public class JwtAuthenticationTokenFilter extends AbstractAuthenticationProcessingFilter {


    public JwtAuthenticationTokenFilter(RequestMatcher requestMatcher) {
        super(requestMatcher);
    }
    
    /**
     * Attempt to authenticate request - basically just pass over to another method to authenticate request headers
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws IOException {

        if(SecurityContextHolder.getContext().getAuthentication() != null){
            log.trace("User has been authenticated already, proceeding");
            return SecurityContextHolder.getContext().getAuthentication();
        }

        String header = request.getHeader("Authorization");


        if (header == null || !header.startsWith("Bearer ")) {
            log.trace("No JWT Token found, redirecting to login");
            response.sendRedirect("/api/login");
            return null;
        }

        log.trace("JWT token in the request: {}", header);

        // mind the 'BEARER ' string
        String authToken = header.substring(7);

        if(authToken.startsWith("\"") && authToken.endsWith("\"")){
            authToken = authToken.substring(1, authToken.length()-1);
        }

        authToken = new String(Base64Utils.decodeFromUrlSafeString(authToken), Charset.forName("UTF-8"));

        log.trace("Extracted JWT token: {}", authToken);

        JwtAuthenticationToken authRequest = new JwtAuthenticationToken(authToken);

        return getAuthenticationManager().authenticate(authRequest);
    }
    /**
     * Make sure the rest of the filterchain is satisfied
     *
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        // As this authentication is in HTTP header, after success we need to continue the request normally
        // and return the response as if the resource was not secured at all
        chain.doFilter(request, response);
    }
}

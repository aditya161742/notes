
# WebApplicationInitializer :---

Reference: http://zetcode.com/spring/webapplicationinitializer/


WebApplicationInitializer interface is used for booting Spring web applications. WebApplicationInitializer registers a Spring DispatcherServlet and creates a Spring web application context. Mostly, developers use AbstractAnnotationConfigDispatcherServletInitializer, which is an implementation of the WebApplicationInitializer, to create Spring web applications.

WebApplicationInitializer contains only one method i.e onStartUp(ServletContext servletContext)

Traditionally, Java web applications based on Servlets were using web.xml file to configure a Java web application. Since Servlet 3.0, web applications can be created programatically via Servlet context listeners.


Ex:

MyWebInitializer.java

package com.zetcode.config;

import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

public class MyWebInitializer implements WebApplicationInitializer {

    @Override
    public void onStartup(ServletContext servletContext) throws ServletException {

        var ctx = new AnnotationConfigWebApplicationContext();
        ctx.register(WebConfig.class);
        ctx.setServletContext(servletContext);

        var servlet = servletContext.addServlet("dispatcher", new DispatcherServlet(ctx));
        servlet.setLoadOnStartup(1);
        servlet.addMapping("/");
    }
}




WebConfig.java

package com.zetcode.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@Configuration
@EnableWebMvc
@ComponentScan(basePackages = "com.zetcode")
public class WebConfig {
}


The WebConfig enables Spring MVC annotations with @EnableWebMvc and configures component scanning for the com.zetcode package.

-------------------------

Very important Reference about AbstractAnnotationConfigDispatcherServletInitializer class methods: https://stackoverflow.com/questions/35258758/getservletconfigclasses-vs-getrootconfigclasses-when-extending-abstractannot

Refrence:-- https://stackoverflow.com/questions/26676782/when-use-abstractannotationconfigdispatcherservletinitializer-and-webapplication

With the release of the Servlet 3.0 spec it became possible to configure your Servlet Container with (almost) no xml. For this there is the ServletContainerInitializer in the Servlet specification. In this class you can register filters, listeners, servlets etc. as you would traditionally do in a web.xml.

Spring provides a an implementation the SpringServletContainerInitializer which knows how to handle WebApplicationInitializer classes. Spring also provides a couple of base classes to extend to make your life easier the AbstractAnnotationConfigDispatcherServletInitializer is one of those. It registers a ContextLoaderlistener (optionally) and a DispatcherServlet and allows you to easily add configuration classes to load for both classes and to apply filters to the DispatcherServlet and to provide the servlet mapping.

Spring provides implementation of SpringServletContainerInitializer interface: 
1) AbstractDispatcherServletInitializer 
2) AbstractAnnotationConfigDispatcherServletInitializer

The WebMvcConfigurerAdapter is for configuring Spring MVC, the replacement of the xml file loaded by the DispatcherServlet for configuring Spring MVC. The WebMvcConfigurerAdapter should be used for a @Configuration class.


Ex: 

@Configuration
@EnableWebMvc
public class WebConfiguration 
    extends WebMvcConfigurerAdapter implements WebApplicationInitializer
{ ... }


I wouldn't recommend mixing those as they are basically 2 different concerns. The first is for configuring the servlet container, the latter for configuring Spring MVC.

You would want to split those into 2 classes.

For the configuration.

@Configuration
@EnableWebMvc
public class WebConfiguration extends WebMvcConfigurerAdapter { ... }
For bootstrapping the application.

public class MyWebApplicationInitializer
    extends AbstractAnnotationConfigDispatcherServletInitializer
{

    protected Class<?>[] getRootConfigClasses() {
        return new Class[] {RootConfig.class};
    }

    protected Class<?>[] getServletConfigClasses()  {
        return new Class[] {WebConfiguration .class};
    }

    protected String[] getServletMappings() {
        return new String[] {"/"};
    }

}

An added advantage is that you now can use the convenience classes provided by Spring instead of manually configuring the DispatcherServlet and/or ContextLoaderListener.


To start from the beginning it is worth looking into how servlet container starts.

SpringServletContainerInitializer is bootstrapped automatically by any Servlet 3.0 container.
SpringServletContainerInitializer looks for classes implementing WebApplicationInitializer.
So to start - SpringServletContainerInitializer has to find the right class implementing WebApplicationInitializer. There are two ways of making it happen:

One is by implementing WebApplicationInitializer on its own; the interface was introduced in Spring 3.1
The second is by extending AbstractAnnotationConfigDispatcherServletInitializer class which also implements WebApplicationInitializer. The class was introduced in Spring 3.2 for convenience and it is "the preferred approach for applications that use Java-based Spring configuration." - see the link. It enables you to start servlet application context as well as root application context.
I would also like to higlight that WebMvcConfigurerAdapter you mention should not be confused with WebApplicationInitializer. As it name suggests - it has to do with configuring "Mvc". It is an adapter class that implements empty methods from WebMvcConfigurer. You use it when you configure your Mvc controller with @EnableWebMvc annotation.

-------------------------------------------------------------------------------------------------------------


# AbstractSecurityWebApplicationInitializer :

Reference: https://www.logicbig.com/tutorials/spring-framework/spring-security/spring-security-components-and-configuration.html


This class implements Spring's WebApplicationInitializer.  The onStartup() method of this class, creates an instance of AnnotationConfigWebApplicationContext which registers client side @Configuration classes with it and bootstraps Spring container.


public class AppSecurityInitializer extends AbstractSecurityWebApplicationInitializer {
  public AppSecurityInitializer() {
      super(MyAppConfig.class);
  }
}


Note that, it's not necessary to call super(MyAppConfig.class) from the constructor, if our configuration class is already registered via DispatcherServlet (if it's Spring MVC application)

AbstractSecurityWebApplicationInitializer also registers an instance of DelegatingFilterProxy. The DelegatingFilterProxy#targetBeanName property is set with bean name "springSecurityFilterChain".

The bean named "springSecurityFilterChain" is registered in the configuration imported by @EnableWebSecurity


DelegatingFilterProxy can be used as a proxy for a standard Servlet Filter.

DelegatingFilterProxy itself is a Servlet Filter which delegates to a specified Spring-managed bean that implements the Filter interface.

We need to set DelegatingFilterProxy's "targetBeanName" property as the target bean name (the bean which implements Filter interface).


Proxy in Java. Proxy is a structural design pattern that provides an object that acts as a substitute for a real service object used by a client. A proxy receives client requests, does some work (access control, caching, etc.) and then passes the request to a service object.


Example:


@Component("myTestFilter")
public class MyFilter implements Filter {
  
  @Autowired
  private MyService myService;
  
  @Override
  public void init (FilterConfig filterConfig) throws ServletException {
  }
  
  @Override
  public void doFilter (ServletRequest request, ServletResponse response,
                        FilterChain chain)
            throws IOException, ServletException {
      System.out.println("-- In MyFilter --");
      HttpServletRequest req = (HttpServletRequest) request;
      myService.doSomething(req);
      chain.doFilter(request, response);
  }
  
  @Override
  public void destroy () {
      
  }
}


@Component
public class MyService {

  public void doSomething (HttpServletRequest req) {
      System.out.println("In MyService: " + req.getRequestURI());
  }
}



@EnableWebMvc
@Configuration
@ComponentScan
public class MyWebConfig {
}



public class AppInitializer extends
        AbstractAnnotationConfigDispatcherServletInitializer {
    .............
  @Override
  protected Filter[] getServletFilters () {
      DelegatingFilterProxy filterProxy = new DelegatingFilterProxy();
      filterProxy.setTargetBeanName("myTestFilter");
      return new Filter[]{filterProxy};
  }
    .............
}


@Controller
@RequestMapping("/**")
public class MyController {
  
  @RequestMapping
  @ResponseBody
  public String handleRequest () {
      System.out.println("-- handling request in controller --");
      return "dummy response";
  }
}



-----------------------------------------------------------------------------------

@EnableWebSecurity:

This annotation is used on our configuration class to important necessary Spring security configuration. Following is the typical usage of the annotation:

@Configuration
@EnableWebSecurity
public class MyAppConfig{
    ....
}

Let's see how the annotation @EnableWebSecurity is defined:

 ..
@Import({ WebSecurityConfiguration.class, SpringWebMvcImportSelector.class })
@EnableGlobalAuthentication
@Configuration
public @interface EnableWebSecurity {
 ....
}

Let's understand what WebSecurityConfiguration and SpringWebMvcImportSelector configuration classes do.


Configurations imported by WebSecurityConfiguration
WebSecurityConfiguration creates a Filter and registers it as a bean by name "springSecurityFilterChain".

FilterChainProxy As the name suggests this Filter bean is another proxy (within DelegatingFilterProxy) which delegates to a list of Spring-managed filter beans (they also implement Filter interface).

Filter-beans list: https://www.logicbig.com/tutorials/spring-framework/spring-security/spring-security-components-and-configuration/images/filters.png

WebSecurity is nothing but builder to create an instance of FilterChainProxy. Its another sibling-class HttpSecurity allows configuring web based security for specific http requests. WebSecurity and HttpSecurity is passed as parameter in two different configure methods when extending spring security class with WebSecurityConfigurerAdapter.

WebSecurityConfigurerAdapter It is implemented by the client application (usually by @Configuration class) to customize WebSecurity and HttpSecurity. It is an adapter implementation of WebSecurityConfigurer. Its init() method creates an instance of HttpSecurity which is responsible to add all the Filters.


@EnableGlobalAuthentication, The annotation @EnableWebSecurity (section 2) is also meta-annotated with @EnableGlobalAuthentication which imports AuthenticationConfiguration. This configuration register beans for authentication process.

With this import we can configure a global instance of AuthenticationManagerBuilder. For example:


@Configuration
@EnableWebSecurity
public class MyAppConfig extends WebSecurityConfigurerAdapter {

  @Override
  public void configure(AuthenticationManagerBuilder builder)
          throws Exception {
      builder.inMemoryAuthentication()
             .withUser("joe")
             .password("123")
             .roles("ADMIN");
  }
  ........
}


-----------------------------------------------------------------------------------------------------------

HTTP Basic Authentication Work in Spring Security ??

Reference: https://dzone.com/articles/how-does-http-basic-authentication-work-in-spring?fromrel=true


when you use HTTP basic for authentication purposes, the client, e.g. your browser or a REST client, sends login credentials in the HTTP request header. 

The header is aptly named as "Authorization," and it contains Base64-encoded string, which is created by concatenating the username and password using a colon.

For example, if the username is "johnsmith"  and the password is "JOHN3214," then they will be concatenated as"johnsmith:JOHN3214" before encoded using Base64 encoding algorithms.

The server, when it receives such a request, it extracts the value of the "Authorization" header and decodes the content of this header using the same algorithm Base64 for authenticating the user.

We use <http-basic>l; in the XML configuration or the httpBasic() method on the HttpSecurity object to enable basic authentication.

When you use the <http-basic>l; configuration element, Spring Security's BasicAuthenticationFitler comes into the picture, which basically checks to see if the incoming HTTP request contains the "Authorization" header or not and its value starts with "Basic."

A BasicAuthenticationEntryPoint strategy is also configured into the  ExceptionTranslationFilter  on startup, which is required to handle requests that do not contain the "Authorization" header.

When you make an HTTP request to a protected URL, e.g. /admin/users from the browser without adding the "Authorization" header, then Spring Security throws an access-denied exception that is handled by the ExceptionTranslationFilter .

This filter then delegates to a particular implementation strategy of the AuthenticationEntryPoint   interface, which is the BasicAuthenticationEntryPoint in our case.

This class adds the header "WWW-Authenticate: Basic real="Spring Security Application" to the response and then sends an HTTP status code of 401 (Unauthorized) to the client, e.g. to your browser, which knows how to handle this code and work accordingly.

When you put the username and password and submit the request, the request again follows the filter chain until it reaches the BasicAuthenticationFilter.

This filter checks the request headers and the location for the Authorization header, starting with "Basic." It will look something like this: Authorization: Basic CDWhZGRpbjpvcGVuc2AzYW1l .

The BasicAuthentictionFilter then extracts the content of the Authorization header and uses the Base64 algorithm to decode the login credentials to extract the username and password from the decoded string.

Once it has that information, the filter creates a UsernamePasswordAuthenticationToken object and sends it to the authentication manager for authentication in the standard way.


The authentication manager will ask the authentication provider ( in memory, JDBC backed or LDAP based) to retrieve the user and then create an Authentication object with it. This process is standard and independent of using HTTP basic for authentication and is applicable for digest authentication, as well.

If you are working in RESTful web services, you can also use the curl command to send the HTTP request with the Authorization error for HTTP basic authentication. I have found curl to be an easy way to test web services by sending various HTTP command from the command line.

As I have said before, basic authentication is not secure. Anyone who can intercept the request can decode the password, hence it is only used for testing purposes, while more sophisticated digest authentication and OAuth  is used in the real-world application, particularly if you are want to secure your REST API.

----------------------------------------------------------------------------------------


Java configuration was added to the Spring framework in Spring 3.1 and extended to Spring Security in Spring 3.2 and is defined in a class annotated @Configuration.


# WebSecurity 

Your example means that Spring (Web) Security is ignoring URL patterns that match the expression you have defined ("/static/**"). This URL is skipped by Spring Security, therefore not secured.

Ex:

@Override
public void configure(WebSecurity web) throws Exception {
    web
        .ignoring()
        .antMatchers("/resources/**")
        .antMatchers("/publics/**");
}

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/admin/**").hasRole("ADMIN")
        .antMatchers("/publics/**").hasRole("USER") // no effect
        .anyRequest().authenticated();
}

WebSecurity in the above example lets Spring ignore /resources/** and /publics/**. Therefore the .antMatchers("/publics/**").hasRole("USER") in HttpSecurity is unconsidered.

-----------------------------------------------------------------------------------------------------------

HttpSecurity, WebSecurity and AuthenticationManagerBuilder ?

configure(AuthenticationManagerBuilder) is used to establish an authentication mechanism by allowing AuthenticationProviders (in-memory, JDBC, LDAP etc) to be added easily: e.g. The following defines the in-memory authentication with the in-built 'user' and 'admin' logins.

public void configure(AuthenticationManagerBuilder auth) {
    auth
        .inMemoryAuthentication()
        .withUser("user")
        .password("password")
        .roles("USER")
    .and()
        .withUser("admin")
        .password("password")
        .roles("ADMIN","USER");
}
configure(HttpSecurity) allows configuration of web based security at a resource level, based on a selection match - e.g. The example below restricts the URLs that start with /admin/ to users that have ADMIN role, and declares that any other URLs need to be successfully authenticated.

protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated()
}
configure(WebSecurity) is used for configuration settings that impact global security (ignore resources, set debug mode, reject requests by implementing a custom firewall definition). For example, the following method would cause any request that starts with /resources/ to be ignored for authentication purposes.

public void configure(WebSecurity web) throws Exception {
    web
        .ignoring()
        .antMatchers("/resources/**");
}


----------------------------------------------------------------------------------------------------------

# Difference between @Autowired AuthenticationManager and @Override configure(AuthenticationManagerBuilder auth)


@Configuration
@EnableWebSecurity
public class CustomWebSecurityConfig extends WebSecurityConfigurerAdapter {
     
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
                .withUser("admin").password("admin").roles("USER");
    }
}


@Configuration
@EnableWebSecurity
public class CustomWebSecurityConfig extends WebSecurityConfigurerAdapter {
     
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
            .withUser("admin").password("admin").roles("USER");
    }
}


configureGlobal makes the AuthenticationManager available to the entire application (i.e. other WebSecurityConfigurerAdapter instances, method security, etc)

The protected configure is like an anonymous inner bean where the scope is limited to that of this WebSecurityConfigurerAdapter.

If you need it exposed as a Bean, you can use authenticationManagerBean.

---------------------------------------------------------------------------------------------------------

# AuthenticationManager, AuthenticationProvider, Multiple AuthenticationProvider

Reference: https://dzone.com/articles/spring-security-authentication



Very Important: Play with antMatchers in real life. Execution is going from left to right.
---------------------------------------------------------------------------------------------------------

# CSRF in spring:

Ref: https://www.baeldung.com/spring-security-csrf

# How is CSRF token verified?


Server issues a random string which is set as the session cookie, and a value for the hidden field in the form.
On the form submit, the server checks the session cookie with the hidden field value for equality, if values are not equal it won't process the request.




--------------------------------------------------------------------------------------------------------


# Spring Security Session 

-> We can control exactly when our session gets created and how Spring Security will interact with it:

always – a session will always be created if one doesn't already exist
ifRequired – a session will be created only if required (default)
never – the framework will never create a session itself but it will use one if it already exists
stateless – no session will be created or used by Spring Security


Ex:

@Override
protected void configure(HttpSecurity http) throws Exception {
    http.sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
}

-> It's very important to understand that this configuration only controls what Spring Security does – not the entire application. Spring Security may not create the session if we instruct it not to, but our app may!

By default, Spring Security will create a session when it needs one – this is “ifRequired“.

For a more stateless application, the “never” option will ensure that Spring Security itself will not create any session; however, if the application creates one, then Spring Security will make use of it.

Finally, the strictest session creation option – “stateless” – is a guarantee that the application will not create any session at all.


-> Before executing the Authentication process, Spring Security will run a filter responsible with storing the Security Context between requests – the SecurityContextPersistenceFilter.

For the strict create-session=”stateless” attribute, this strategy will be replaced with another – NullSecurityContextRepository – and no session will be created or used to keep the context.


-> Store our own session objects rather then username in session object created by spring security.

-> When you want custom authentication in Spring Security you can either implement a custom AuthenticationProvider or custom UserDetailsService.

In case of implenting UserDetailsService we can extend User of userDetails of spring framework and then call extended class inside loadByUsername method, it will return object of custom class along with User class objects.

Below is the example using AuthenticationProvider 

Ex:


@Component
public class AuthenticationProviderBean implements AuthenticationProvider {

@Autowired
private UserloginDAO userloginDAO;

@Override
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String username = authentication.getName();
    String password = null;
    User user = userloginDAO.getUsername(username);
    if(user == null || !userLoginDAO.auth(user.getPassword(), password)){
        throw new BadCredentialsException("Login Unauthenticated");
    }
    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,
                            password, Arrays.asList(new MyGrantedAuthority(user)));
    token.setDetails(user);
    return token;
}

@Override
public boolean supports(Class<?> authentication) {
    return authentication.equals(UsernamePasswordAuthenticationToken.class);
}

public class MyGrantedAuthority implements GrantedAuthority{

    private static final long serialVersionUID = 5202669007419658413L;

    private UserData user;

    public MyGrantedAuthority() {
        super();
    }

    public MyGrantedAuthority(UserData user){
        this.user = user;
    }

    @Override
    public String getAuthority() {
        return user.getRole();
    }

}
}



Then get session data by:

 User user = (User)SecurityContextHolder.getContext().getAuthentication.getDetails();



Below is the example using UserDetailsService:

Steps:

1) Extend spring User (org.springframework.security.core.userdetails.User) class and what ever properties you need.
2) Extend spring UserDetailsService (org.springframework.security.core.userdetails.UserDetailsService) and fill the above object. Override loadUserByUsername and return your extended user class
3) Set your custom UserDetailsSe


Ref: -- https://stackoverflow.com/questions/20349594/adding-additional-details-to-principal-object-stored-in-spring-security-context

Ex:

public class CurrentUser extends User{

   //This constructor is a must
    public CurrentUser(String username, String password, boolean enabled, boolean accountNonExpired,
            boolean credentialsNonExpired, boolean accountNonLocked,
            Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }
    //Setter and getters are required
    private String firstName;
    private String lastName;

}


@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

@Override
public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {

    //Try to find user and its roles, for example here we try to get it from database via a DAO object
   //Do not confuse this foo.bar.User with CurrentUser or spring User, this is a temporary object which holds user info stored in database
    foo.bar.User user = userDao.findByUserName(username);

    //Build user Authority. some how a convert from your custom roles which are in database to spring GrantedAuthority
    List<GrantedAuthority> authorities = buildUserAuthority(user.getUserRole());

    //The magic is happen in this private method !
    return buildUserForAuthentication(user, authorities);

}


//Fill your extended User object (CurrentUser) here and return it
private User buildUserForAuthentication(foo.bar.User user, 
List<GrantedAuthority> authorities) {
    String username = user.getUsername();
    String password = user.getPassword();
    boolean enabled = true;
    boolean accountNonExpired = true;
    boolean credentialsNonExpired = true;
    boolean accountNonLocked = true;

    return new CurrentUser(username, password, enabled, accountNonExpired, credentialsNonExpired,
            accountNonLocked, authorities);
   //If your database has more information of user for example firstname,... You can fill it here 
  //CurrentUser currentUser = new CurrentUser(....)
  //currentUser.setFirstName( user.getfirstName() );
  //.....
  //return currentUser ;
}

private List<GrantedAuthority> buildUserAuthority(Set<UserRole> userRoles) {

    Set<GrantedAuthority> setAuths = new HashSet<GrantedAuthority>();

    // Build user's authorities
    for (UserRole userRole : userRoles) {
        setAuths.add(new SimpleGrantedAuthority(userRole.getRole()));
    }

    return new ArrayList<GrantedAuthority>(setAuths);
}

}


# Session Fixation:

-> In a Session Fixation attack, a victim is tricked into using a particular Session ID which is known to the attacker. The attacker is able to fool the vulnerable application into treating their malicious requests as if they were being made by the legitimate owner of the session.

-> The framework offers protection against typical Session Fixation attacks by configuring what happens to an existing session when the user tries to authenticate again:

Ex:

http.sessionManagement()
  .sessionFixation().migrateSession()

 By default, Spring Security has this protection enabled (“migrateSession“) – on authentication a new HTTP Session is created, the old one is invalidated and the attributes from the old session are copied over.

 # Handling Session Timeout 

 -> After the session has timed out, if the user sends a request with an expired session id, they will be redirected to a URL configurable via the namespace:

-> Similarly, if the user sends a request with a session id which is not expired, but entirely invalid, they will also be redirected to a configurable URL:

Ex: 

http.sessionManagement()
  .expiredUrl("/sessionExpired.html")
  .invalidSessionUrl("/invalidSession.html");


# Concurrent Session Control

-> When a user that is already authenticated tries to authenticate again, the application can deal with that event in one of a few ways. It can either invalidate the active session of the user and authenticate the user again with a new session, or allow both sessions to exist concurrently.

-> The first step in enabling the concurrent session-control support is to add the following listener

Ex:

@Bean
public HttpSessionEventPublisher httpSessionEventPublisher() {
    return new HttpSessionEventPublisher();
}

This is essential to make sure that the Spring Security session registry is notified when the session is destroyed.
And to override multiple concurrent session for same user.

Ex: 

@Override
protected void configure(HttpSecurity http) throws Exception {
    http.sessionManagement().maximumSessions(2)
}




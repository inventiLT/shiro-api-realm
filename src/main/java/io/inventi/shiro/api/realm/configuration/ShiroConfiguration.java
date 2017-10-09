package io.inventi.shiro.api.realm.configuration;

import io.inventi.shiro.api.realm.domain.UserToken;
import io.inventi.shiro.api.realm.service.AuthorizationExceptionHandler;
import io.inventi.shiro.api.realm.service.ApiRealm;
import io.inventi.shiro.api.realm.service.LdapService;
import io.inventi.shiro.api.realm.service.PreAuthFilter;
import io.inventi.shiro.api.realm.service.UserService;
import io.inventi.shiro.api.realm.service.UserServiceImpl;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.DefaultWebSessionStorageEvaluator;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;

@Configuration
public class ShiroConfiguration {

    @Value("${users.endpoint}")
    public String usersEndpoint;

    @Value("${ldap.endpoint}")
    public String ldapEndpoint;

    @Bean
    public static PropertySourcesPlaceholderConfigurer propertyPlaceholderConfigurer() {
        return new PropertySourcesPlaceholderConfigurer();
    }

    @Bean
    public UserService userService() {
        return new UserServiceImpl(usersEndpoint, new RestTemplateBuilder());
    }

    @Bean
    public LdapService ldapService() {
        return new LdapService(ldapEndpoint, new RestTemplateBuilder());
    }

    @Bean
    public Realm realm() {
        ApiRealm realm = new ApiRealm(userService());
        realm.setCachingEnabled(false);
        realm.setAuthenticationTokenClass(UserToken.class);
        realm.setCredentialsMatcher(new AllowAllCredentialsMatcher());
        return realm;
    }

    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean() {
        ShiroFilterFactoryBean shiroFilterFactory = new ShiroFilterFactoryBean();
        shiroFilterFactory.setSecurityManager(securityManager());
        shiroFilterFactory.getFilters().put("preAuthFilter", new PreAuthFilter(ldapService()));
        shiroFilterFactory.getFilterChainDefinitionMap().put("/**", "preAuthFilter[permissive]");
        return shiroFilterFactory;
    }

    @Bean
    public DefaultWebSecurityManager securityManager() {
        DefaultWebSecurityManager dwsm = new DefaultWebSecurityManager();
        dwsm.setRealm(realm());
        dwsm.setSessionManager(new DefaultWebSessionManager());
        dwsm.setSubjectDAO(defaultSubjectDAO());
        return dwsm;
    }

    @Bean
    public DefaultAdvisorAutoProxyCreator getDefaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator daap = new DefaultAdvisorAutoProxyCreator();
        daap.setProxyTargetClass(true);
        return daap;
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor getAuthorizationAttributeSourceAdvisor() {
        AuthorizationAttributeSourceAdvisor aasa = new AuthorizationAttributeSourceAdvisor();
        aasa.setSecurityManager(securityManager());
        return new AuthorizationAttributeSourceAdvisor();
    }

    @Bean
    public DefaultWebSessionStorageEvaluator defaultWebSessionStorageEvaluator() {
        DefaultWebSessionStorageEvaluator evaluator = new DefaultWebSessionStorageEvaluator();
        evaluator.setSessionStorageEnabled(false);
        return evaluator;
    }

    @Bean
    public DefaultSubjectDAO defaultSubjectDAO() {
        DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
        subjectDAO.setSessionStorageEvaluator(defaultWebSessionStorageEvaluator());
        return subjectDAO;
    }

    @Bean
    public AuthorizationExceptionHandler authorizationExceptionHandler() {
        return new AuthorizationExceptionHandler();
    }
}

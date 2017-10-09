package io.inventi.shiro.api.realm.service;

import io.inventi.shiro.api.realm.domain.UserToken;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

public class PreAuthFilter extends AuthenticatingFilter {

    public static final String USERNAME_HEADER = "x-credential-username";
    
    private LdapService ldapService;

    public PreAuthFilter(LdapService ldapService) {
        this.ldapService = ldapService;
    }

    private String getUsernameHeader(ServletRequest request) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        return httpRequest.getHeader(USERNAME_HEADER);
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return executeLogin(request, response);
    }

    @Override
    protected boolean executeLogin(ServletRequest request, ServletResponse response) throws Exception {
        AuthenticationToken token;
        if (isPreAuthRequest(request)) {
            token = createToken(request, response);
        } else {
            token = new UserToken("", false);
        }
        try {
            Subject subject = getSubject(request, response);
            subject.login(token);
            return onLoginSuccess(token, subject, request, response);
        } catch (AuthenticationException e) {
            return onLoginFailure(token, e, request, response);
        }
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        String userId = getUsernameHeader(request);
        return new UserToken(ldapService.resolveUsername(userId), true);
    }

    @Override
    protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
        return true;
    }

    private boolean isPreAuthRequest(ServletRequest request) {
        return getUsernameHeader(request) != null;
    }

}

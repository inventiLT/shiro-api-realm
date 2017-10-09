package io.inventi.shiro.api.realm.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

public class LdapService {

    private static final Logger logger = LoggerFactory.getLogger(LdapService.class);

    private RestTemplate ldapApiTemplate;

    public LdapService(String ldapEndpoint, RestTemplateBuilder restTemplateBuilder) {

        this.ldapApiTemplate = restTemplateBuilder
                .rootUri(ldapEndpoint)
                .build();
    }


    @Cacheable(value = "ldapCache", key = "#dn")
    public String resolveUsername(String dn) throws HttpClientErrorException {
        try {
            return ldapApiTemplate.getForObject("/v1/ldap-username/{dn}",
                    String.class,
                    dn);
        } catch (HttpClientErrorException ex) {
            logger.error("Unable to resolve username from dn {}", dn);
            throw ex;
        }
    }

}

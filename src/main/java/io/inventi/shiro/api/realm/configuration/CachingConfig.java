package io.inventi.shiro.api.realm.configuration;

import org.ehcache.config.CacheConfiguration;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.ResourcePoolsBuilder;
import org.ehcache.core.config.DefaultConfiguration;
import org.ehcache.expiry.Duration;
import org.ehcache.expiry.Expirations;
import org.ehcache.jsr107.EhcacheCachingProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.jcache.JCacheCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.cache.Caching;
import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching
public class CachingConfig {

    @Bean
    public JCacheCacheManager jCacheCacheManager(@Value("${cache.ttl-minutes}") int timeToLiveInMinutes) {
        CacheConfiguration cacheConfiguration = CacheConfigurationBuilder.newCacheConfigurationBuilder(
                Object.class,
                Object.class,
                ResourcePoolsBuilder.heap(1))
                .withExpiry(Expirations.timeToLiveExpiration(new Duration(timeToLiveInMinutes, TimeUnit.MINUTES)))
                .build();

        EhcacheCachingProvider provider = (EhcacheCachingProvider) Caching.getCachingProvider();
        DefaultConfiguration configuration = new DefaultConfiguration(provider.getDefaultClassLoader());
        configuration.addCacheConfiguration("userCache", cacheConfiguration);
        configuration.addCacheConfiguration("ldapCache", cacheConfiguration);
        return new JCacheCacheManager(provider.getCacheManager(provider.getDefaultURI(), configuration));
    }

}

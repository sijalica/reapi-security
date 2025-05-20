package com.reapi.securityAPI.repository;

import org.springframework.data.ldap.repository.LdapRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LdapRegisteredClientRepository extends LdapRepository<RegisteredClient> {
    Optional<RegisteredClient> findByClientId(String clientId);
}

package org.mitre.openid.connect.eid;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class EidAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1008243604974685826L;
    
    private String eid;
    
    public EidAuthenticationToken(String eid, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.eid = eid;
    }
    
    @Override
    public Object getCredentials() {
        return eid;
    }

    @Override
    public Object getPrincipal() {
        return eid;
    }

}

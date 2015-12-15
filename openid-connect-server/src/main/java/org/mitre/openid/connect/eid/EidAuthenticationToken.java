package org.mitre.openid.connect.eid;

import java.security.cert.X509Certificate;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class EidAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1008243604974685826L;
    
    private String eid;
    private X509Certificate certificate;
    
    public EidAuthenticationToken(String eid, X509Certificate certificate, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.eid = eid;
        this.certificate = certificate;
    }
    
    @Override
    public Object getCredentials() {
        return certificate;
    }

    @Override
    public Object getPrincipal() {
        return eid;
    }

}

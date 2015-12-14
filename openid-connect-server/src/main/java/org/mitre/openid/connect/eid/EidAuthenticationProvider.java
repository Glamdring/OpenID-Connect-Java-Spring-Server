package org.mitre.openid.connect.eid;

import org.mitre.openid.connect.service.CitizenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Component
public class EidAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private CitizenService citizenService;
    
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        UserDetails user = citizenService.loadUserByUsername((String) authentication.getPrincipal());
        if (user != null) {
            return authentication; //TODO populate?
        } else {
            return null;
        }
    }

    @Override
    public boolean supports(Class<?> authenticationClass) {
        return EidAuthenticationToken.class.isAssignableFrom(authenticationClass);
    }

}

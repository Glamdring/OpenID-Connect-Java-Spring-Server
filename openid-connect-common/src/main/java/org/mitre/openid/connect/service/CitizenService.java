package org.mitre.openid.connect.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.google.common.collect.Sets;

@Service
public class CitizenService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String eid) throws UsernameNotFoundException {
        System.out.println("Loading user by eid: " + eid);
        boolean expired = false;
        return new User(eid, "p", true, !expired, !expired, !expired, Sets.newHashSet(new SimpleGrantedAuthority("ROLE_USER")));
    }

}

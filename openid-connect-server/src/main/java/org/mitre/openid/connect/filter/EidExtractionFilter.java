/*******************************************************************************
 * Copyright 2015 The MITRE Corporation
 *   and the MIT Kerberos and Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package org.mitre.openid.connect.filter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.mitre.openid.connect.eid.EidAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import com.google.common.collect.Sets;

/**
 * @author bozho
 *
 */
public class EidExtractionFilter extends GenericFilterBean {

	/**
	 * Logger for this class
	 */
	private static final Logger logger = LoggerFactory.getLogger(EidExtractionFilter.class);

	//@Value("") TODO
	private boolean isBehindLoadBalancer = true;

	private CertificateFactory certificateFactory;

	private AuthenticationManager authenticaitonManager;
	
	public EidExtractionFilter(AuthenticationManager authenticationManager) {
	    this.authenticaitonManager = authenticationManager;
	    try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		
		// skip everything that's not an authorize URL
		if (!request.getServletPath().startsWith("/authorize")) {
			chain.doFilter(req, res);
			return;
		}

		X509Certificate userCertificate = null;
		
		if (isBehindLoadBalancer) {
		    String certificateHeader = request.getHeader("X-Request-Certificate"); // see https://serverfault.com/questions/622855/nginx-proxy-to-back-end-with-ssl-client-certificate-authentication
		    if (certificateHeader == null) {
		        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		        return;
		    }
		    // the load balancer (e.g. nginx) forwards the certificate into a header by replacing new lines with whitespaces (2 or more)
		    // also replace tabs, which sometimes nginx may send instead of whitespaces
		    String certificateContent = certificateHeader.replaceAll("\\s{2,}", System.lineSeparator()).replaceAll("\\t+", System.lineSeparator());
	        try {
                userCertificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateContent.getBytes("ISO-8859-11")));
            } catch (CertificateException e) {
                logger.error("Failed to parse certificate: " + certificateContent, e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
		} else {
    		X509Certificate certs[] = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
    		if (certs != null && certs.length > 0) {
    		    userCertificate = certs[0];
    		} else {
    		    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                return;
    		}
		}
		
		String eid = null;
		String dn = userCertificate.getSubjectDN().getName();
        try {
            LdapName ldapDN = new LdapName(dn);
            for (Rdn rdn : ldapDN.getRdns()) {
                if (rdn.getType().equals("CN")) {
                    eid = rdn.getValue().toString();
                }
            }
        } catch (InvalidNameException e) {
            logger.error("Failed to parse certificate CN", e);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
		
		logger.info("EID extracted: " + eid);

		EidAuthenticationToken authRequest = new EidAuthenticationToken(eid, userCertificate, Sets.newHashSet(new SimpleGrantedAuthority("ROLE_USER")));
		Authentication user = authenticaitonManager.authenticate(authRequest);
		SecurityContextHolder.getContext().setAuthentication(user);
	}
}

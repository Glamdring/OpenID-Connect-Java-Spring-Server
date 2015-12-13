<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<o:header title="Log In" />
<script type="text/javascript">
<!--

$(document).ready(function() {
	// select the appropriate field based on context
	$('#<c:out value="${ login_hint != null ? 'j_password' : 'j_username' }" />').focus();
});

//-->
</script>
<o:topbar />
<div class="container-fluid main">

	<h1><spring:message code="login.login_with_username_and_password"/></h1>

	<c:if test="${ param.error != null }">
		<div class="alert alert-error"><spring:message code="login.error"/></div>
	</c:if>


	<div class="row-fluid">
		<div class="span6 offset1 well">
			<form action="${ config.issuer }${ config.issuer.endsWith('/') ? '' : '/' }j_spring_security_check" method="POST">
				<div>
					<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
					<input type="submit" class="btn" value="Authorize" name="submit">
				</div>
			</form>
		</div>
	</div>
</div>

<o:footer/>

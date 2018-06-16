package org.owasp.webgoat.plugin;

import com.google.common.collect.Lists;
import org.jcodings.util.Hash;
import org.owasp.webgoat.assignments.AssignmentEndpoint;
import org.owasp.webgoat.assignments.AssignmentHints;
import org.owasp.webgoat.assignments.AssignmentPath;
import org.owasp.webgoat.assignments.AttackResult;
import org.owasp.webgoat.session.UserSessionData;
import org.owasp.webgoat.session.WebSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import java.util.Map;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Arrays;

/**
 * Created by jason on 1/5/17.
 */

@AssignmentPath("/crypto-task/verify")
@AssignmentHints({"ctr-bypass.hints.verify.1", "ctr-bypass.hints.verify.2", "ctr-bypass.hints.verify.3", "ctr-bypass.hints.verify.4"})
public class VerifyHash extends AssignmentEndpoint {

    @Autowired
    private WebSession webSession;

    @Autowired
    UserSessionData userSessionData;

    @PostMapping(produces = {"application/json"})
    @ResponseBody
    public AttackResult completed(HttpServletRequest req) throws ServletException, IOException {
	// Get form parameters
	String password_input = req.getParameter("password");
	String password = "tajnehaslo";
	// Check if password are equal
	if(password.equals(password_input)){
		// Success
		return trackProgress(success()
            	    .feedback("verify-ctr.success")
	            .build());

	}else{
		return trackProgress(failed()
            	.feedback("verify-ctr.failed")
            	.build());
	}

	
    }
}

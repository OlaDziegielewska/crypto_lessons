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
import java.util.Base64;

/**
 * Created by jason on 1/5/17.
 */

@AssignmentPath("/cbc-flipping/verify")
@AssignmentHints({"cbc-bypass.hints.verify.1", "cbc-bypass.hints.verify.2"})
public class Verify extends AssignmentEndpoint {

    @Autowired
    private WebSession webSession;

    @Autowired
    UserSessionData userSessionData;

    @PostMapping(produces = {"application/json"})
    @ResponseBody
    public AttackResult completed(HttpServletRequest req) throws ServletException, IOException {

	try{
		// Get form parameters
		String iv = req.getParameter("iv");
		String encodedCipher = req.getParameter("cipher");	
	
		byte[] decodedCipher = Base64.getDecoder().decode(encodedCipher.getBytes());	
		CbcCipher enc = new CbcCipher();
		String key = "abcdefghijklmop";
		String adminString = "{\"role\":0,\"u\":1}";
		String userString = "{\"role\":4,\"u\":1}";
		String lamerString = "{\"role\":2,\"u\":1}";
		
		//String iv_str = "AAAAAAAAAAAAAAAA";
		//byte[] encrypted = enc.encrypt(clean, key, iv_str);
		String decrypted = enc.decrypt(decodedCipher, key, iv);

		// Check if hash are equal
		if(decrypted.equals(adminString)){
			// Success
			return trackProgress(success()
		    	    .feedback("cbc-flipping.admin")
//			    .output(decrypted)
			    .build());

		}else if(decrypted.equals(userString)){
                        // Success
                        return trackProgress(success()
                            .feedback("cbc-flipping.user")
  //                          .output(decrypted)
                            .build());

                }else if(decrypted.equals(lamerString)){
                        // Success
                        return trackProgress(success()
                            .feedback("cbc-flipping.lamer")
    //                        .output(decrypted)
                            .build());

                }
		else{
			return trackProgress(failed()
		    	.feedback("cbc-flipping.unknown")
		    	.build());
		}
	}catch(Exception ex){
		return trackProgress(failed()
		    	.feedback("cbc-flipping.error")
			.output(ex.getMessage())
		    	.build());
	}

	
    }


}

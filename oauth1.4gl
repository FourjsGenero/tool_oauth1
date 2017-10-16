IMPORT com
IMPORT xml
IMPORT SECURITY
IMPORT util
IMPORT FGL WSHelper

TYPE typ_identity  RECORD
    key STRING,
    secret STRING,
    owner STRING,
    attributes RECORD 
        s STRING 
    END RECORD,
    principal STRING
END RECORD

TYPE typ_token RECORD
 oauth_token STRING,
 oauth_token_secret STRING,
 oauth_callback_confirmed BOOLEAN
END RECORD

DEFINE g_ident typ_identity
DEFINE g_token typ_token

MAIN
    DEFINE resp STRING

    # Get temporary token
    LET resp = DoAuth1Request("POST","<your_url>",NULL,NULL,g_ident.*, g_token.*)
    IF resp IS NULL THEN
      DISPLAY "Error : unable to get token"
      EXIT PROGRAM 1
    ELSE
      CALL ParseOAuth1RequestTokenResponse(resp) RETURNING g_token.*
    END IF
      
END MAIN

FUNCTION ParseOAuth1RequestTokenResponse(ret)
  DEFINE t typ_token
  DEFINE ret,token,sub STRING
  DEFINE tkz base.StringTokenizer
  DEFINE ind INTEGER 
  LET tkz = base.StringTokenizer.CREATE(ret,"&")
  WHILE tkz.hasMoreTokens()
    LET token = tkz.nextToken()
    LET ind = token.getIndexOf("=",1)
    LET sub = token.subString(1,ind-1)
    CASE sub
      WHEN "oauth_token"
        LET t.oauth_token = token.subString(ind+1, token.getLength())
      WHEN "oauth_token_secret"
        LET t.oauth_token_secret = token.subString(ind+1, token.getLength())
      WHEN "oauth_callback_confirmed"
        LET t.oauth_callback_confirmed = token.subString(ind+1, token.getLength())
    END CASE
  END WHILE
  RETURN t.*
END FUNCTION


FUNCTION sign_hmacsha1(akey,atext)
    DEFINE akey, atext STRING
    DEFINE result STRING
    DEFINE ckey xml.CryptoKey

    LET ckey = xml.CryptoKey.create("http://www.w3.org/2000/09/xmldsig#hmac-sha1")
    CALL ckey.setKey(akey)

    LET result = xml.Signature.signString(ckey,atext)

    RETURN result
END FUNCTION


FUNCTION DoAuth1Request(method, url, queryString, data, user_key, token_key)
  DEFINE req    com.HttpRequest
  DEFINE resp   com.HttpResponse
  DEFINE method STRING
  DEFINE url    STRING
  DEFINE queryString STRING
  DEFINE user_key typ_identity
  DEFINE token_key typ_token
  DEFINE nonce  STRING
  DEFINE data STRING
  DEFINE query          WSHelper.WSQueryType
  DEFINE attrs          WSHelper.WSQueryType  
  DEFINE oauthHeader STRING # For WWW-Authorization
  DEFINE oauthQuery  STRING # For url-encoded-form
  DEFINE timestamp INTEGER
  DEFINE ind    INTEGER
  DEFINE the_key    STRING
  DEFINE signVal    STRING
  DEFINE attVal     base.StringBuffer
  DEFINE buf        base.StringBuffer

  # Create random and timestamp
  LET nonce = security.RandomGenerator.CreateUUIDString()
  LET timestamp = util.Datetime.toSecondsSinceEpoch(CURRENT)

  # Add OAuth 1 attributes
  LET oauthHeader = "oauth_consumer_key=\""||user_key.key||"\","
  LET oauthQuery = "oauth_consumer_key="||user_key.key||"&"
  LET attrs[1].NAME="oauth_consumer_key"
  LET attrs[1].VALUE=user_key.key
  
  LET oauthHeader = oauthHeader || "oauth_signature_method=\"HMAC-SHA1\","
  LET oauthQuery = oauthQuery || "oauth_signature_method=HMAC-SHA1&"
  LET attrs[2].NAME="oauth_signature_method"
  LET attrs[2].VALUE="HMAC-SHA1"
  
  LET oauthHeader = oauthHeader || "oauth_nonce=\""||nonce||"\","
  LET oauthQuery = oauthQuery || "oauth_nonce="||nonce||"&"
  LET attrs[3].NAME="oauth_nonce"
  LET attrs[3].VALUE=nonce

  LET oauthHeader = oauthHeader || "oauth_timestamp=\""||timestamp||"\","
  LET oauthQuery = oauthQuery || "oauth_timestamp="||timestamp||"&"
  LET attrs[4].NAME="oauth_timestamp"
  LET attrs[4].VALUE=timestamp      

  LET oauthHeader = oauthHeader || "oauth_version=\"1.0\","
  LET oauthQuery = oauthQuery || "oauth_version=1.0&"
  LET attrs[5].NAME="oauth_version"
  LET attrs[5].VALUE="1.0" 

  LET oauthHeader = oauthHeader || "oauth_callback=\"oob\","
  LET oauthQuery = oauthQuery || "oauth_version=oob&"
  LET attrs[6].NAME="oauth_callback"
  LET attrs[6].VALUE="oob" 
  
  IF token_key.oauth_token IS NOT NULL THEN
    LET oauthHeader = oauthHeader || "oauth_token=\""||token_key.oauth_token||"\","
    LET oauthQuery = oauthQuery || "oauth_token="||token_key.oauth_token||"&"
    LET attrs[7].NAME="oauth_token"
    LET attrs[7].VALUE=token_key.oauth_token
  END IF
  
  # Create Request according to query string and method
  IF queryString IS NOT NULL THEN
    LET req = com.HttpRequest.CREATE(url||"?"||queryString)
    CALL req.setMethod(method)
    
    CALL WSHelper.SplitQueryString(queryString) RETURNING query
    CALL AppendQueries(attrs, query)
    
  ELSE
    LET req = com.HttpRequest.CREATE(url)
    CALL req.setMethod(method)
  END IF

  IF data THEN
    CALL WSHelper.SplitQueryString(data) RETURNING query
    CALL AppendQueries(attrs, query)
  END IF

  # Normalize parameters
  IF attrs.getLength()>0 THEN
    # URL encode parameters
    FOR ind = 1 TO attrs.getLength()
      LET attrs[ind].NAME = util.Strings.urlEncode(attrs[ind].name)
      LET attrs[ind].value = util.Strings.urlEncode(attrs[ind].value)
    END FOR
    # then sort them
    CALL attrs.SORT("name",FALSE)
    # then create concatenate string
    LET attVal = base.StringBuffer.CREATE()
    FOR ind = 1 TO attrs.getLength()
      CALL attVal.APPEND(attrs[ind].name)
      CALL attVal.APPEND("=")
      CALL attVal.APPEND(attrs[ind].VALUE)
      IF ind<attrs.getLength() THEN
        CALL attVal.APPEND("&")
      END IF
    END FOR
  END IF
  
  # Normalize request with OAuthV1 standard
  LET buf = base.StringBuffer.CREATE()
  
  # Method
  CALL buf.APPEND(method.toUpperCase())
  CALL buf.APPEND("&")
  
  # URL 
  # FIXME : only scheme and host must be in lower
  CALL buf.APPEND(util.Strings.urlEncode(url.toLowerCase()))
  
  # Attributes (query string and post data)
  IF attVal.getLength()>0 THEN
    CALL buf.APPEND("&")
    CALL buf.APPEND( util.Strings.urlEncode(attVal.toString()))
  END IF

  DISPLAY "Normalized:",buf.toString()

  # Create HMAC key from client and token secret (if any)
  LET the_key = util.Strings.urlEncode(user_key.secret)||"&"
  IF token_key.oauth_token IS NOT NULL THEN
    LET the_key = the_key || util.Strings.urlEncode(token_key.oauth_token_secret)
  END IF  
  DISPLAY "The Key:",the_key
  
  # Sign normalized string
  LET signVal = sign_hmacsha1(the_key, buf.toString())

  DISPLAY "The Signature:",signVal

  # Append signature to OAuth header
  LET oauthHeader = oauthHeader || "oauth_signature=\""|| util.Strings.urlEncode(signVal)||"\""
  LET oauthQuery = oauthQuery || "oauth_signature="|| util.Strings.urlEncode(signVal)

  IF data IS NOT NULL THEN
    # Set OAuth header to request
    CALL req.setHeader("Authorization", "OAuth "||oauthHeader)
    CALL req.doFormEncodedRequest(data, TRUE)
  ELSE
    CALL req.setHeader("Authorization", "OAuth "||oauthHeader)
    CALL req.doFormEncodedRequest(oauthQuery, TRUE)
  END IF

  LET resp = req.getResponse()
  IF resp.getStatusCode()==200 THEN
    RETURN resp.getTextResponse()
  ELSE
    RETURN NULL
  END IF
END FUNCTION


FUNCTION AppendQueries(ret, _add)
  DEFINE ret, _add WSHelper.WSQueryType
  DEFINE ind    INTEGER
  FOR ind = 1 TO _add.getLength()
    CALL ret.appendElement()
    LET ret[ret.getLength()].* = _add[ind].*
  END FOR
END FUNCTION
  
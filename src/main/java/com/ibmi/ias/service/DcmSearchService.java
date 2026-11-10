package com.ibmi.ias.service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Verified IBM i GSKit SSL/TLS Return Code Lookup and ADMIN3 Log Analyzer Service.
 * Source reference: QSYSINC/H(GSKSSL), /QIBM/include/gskssl.h, and standard EBCDIC CP037 character mapping.
 */
public class DcmSearchService {

    public static class GskDetail {
        public long code;
        public String constant;
        public String originFunction;
        public String serviceProgram;
        public String targetObject;
        public String failureDomain;
        public String rootCause;
        public List<String> recoveryCommands = new ArrayList<>();

        public GskDetail(long code, String constant, String originFunction, String serviceProgram, String targetObject, String failureDomain, String rootCause, String... cmds) {
            this.code = code;
            this.constant = constant;
            this.originFunction = originFunction;
            this.serviceProgram = serviceProgram;
            this.targetObject = targetObject;
            this.failureDomain = failureDomain;
            this.rootCause = rootCause;
            if (cmds != null) {
                this.recoveryCommands.addAll(Arrays.asList(cmds));
            }
        }
    }

    private final Map<Long, String> gsksslCodes = new HashMap<>();
    private final Map<Long, GskDetail> gskDetails = new HashMap<>();

    // Standard IBM EBCDIC Code Page 037 (CP037) to ASCII mapping table
    private static final int[] EBCDIC_CP037 = new int[] {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        32,0,0,0,0,0,0,0,0,0,0,46,60,40,43,124,
        38,0,0,0,0,0,0,0,0,0,33,36,42,41,59,94,
        45,47,0,0,0,0,0,0,0,0,124,44,37,95,62,63,
        0,0,0,0,0,0,0,0,0,96,58,35,64,39,61,34,
        0,97,98,99,100,101,102,103,104,105,0,0,0,0,0,0,
        0,106,107,108,109,110,111,112,113,114,0,0,0,0,0,0,
        0,126,115,116,117,118,119,120,121,122,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        123,65,66,67,68,69,70,71,72,73,0,0,0,0,0,0,
        125,74,75,76,77,78,79,80,81,82,0,0,0,0,0,0,
        92,0,83,84,85,86,87,88,89,90,0,0,0,0,0,0,
        48,49,50,51,52,53,54,55,56,57,0,0,0,0,0,0
    };

    public DcmSearchService() {
        initDatabase();
    }

    private void initDatabase() {
        // Official GSKit Return Codes from /QIBM/include/gskssl.h
        addGskCode(0L, "GSK_OK", "gsk_secure_soc_init()", "GSKit", "Session Active", "Normal Execution", "Operation completed successfully.");
        addGskCode(1L, "GSK_INVALID_HANDLE", "gsk_secure_soc_init()", "GSKit", "Handle Reference", "API Parameter Error", "An invalid environment or secure socket handle was specified.");
        addGskCode(2L, "GSK_API_NOT_AVAILABLE", "gsk_secure_soc_init()", "GSKit", "Cryptographic Engine", "Subsystem Unavailable", "The requested cryptographic API is not available on the system.");
        addGskCode(3L, "GSK_INTERNAL_ERROR", "gsk_secure_soc_init()", "GSKit", "Internal Routine", "Subsystem Fault", "An unexpected internal cryptographic subsystem error occurred.");
        addGskCode(4L, "GSK_INSUFFICIENT_STORAGE", "gsk_environment_init()", "GSKit", "System Memory", "Resource Exhaustion", "Insufficient system memory / storage available for operation.");
        addGskCode(5L, "GSK_NO_KEYFILE_PASSWORD", "gsk_environment_init()", "GSKit", "/QIBM/UserData/ICSS/Cert/Server/DEFAULT.STH", "Key Database Security", "No password was supplied to access the key database.");
        addGskCode(6L, "GSK_KEYFILE_CERT_EXPIRED", "gsk_secure_soc_init()", "GSKit", "Key Store Certificate", "Certificate Expiration", "The certificate in the keyfile is expired.");
        addGskCode(7L, "GSK_ERROR_LOAD_GSK", "gsk_environment_init()", "GSKit", "GSKit Dynamic Library", "Library Load Failure", "Unable to dynamically load the GSKit runtime library.");
        addGskCode(8L, "GSK_ERROR_CERT_VALIDATION", "gsk_secure_soc_init()", "GSKit", "Peer / CA Certificate", "Certificate Validation", "Certificate validation failed.");
        addGskCode(201L, "GSK_KEYFILE_INVALID_FORMAT", "gsk_environment_init()", "GSKit", "DEFAULT.KDB", "Key Store Format", "Key database file format is invalid or corrupted.");
        addGskCode(202L, "GSK_KEYFILE_INVALID_PASSWORD", "gsk_environment_init()", "GSKit", "DEFAULT.STH", "Key Store Authentication", "Incorrect password supplied for key database or stash file mismatch.");
        addGskCode(406L, "GSK_ERROR_IO", "gsk_secure_soc_read()", "GSKit", "TCP/IP Socket", "Socket I/O", "Low-level socket communication failure or abrupt TCP connection reset.", "NETSTAT *CNN", "WRKJOB JOB(*)");
        addGskCode(407L, "GSK_ERROR_BAD_KEYFILE_LABEL", "gsk_environment_init()", "GSKit", "DEFAULT.KDB", "Certificate Label", "Specified certificate label was not found in the key database.");
        addGskCode(408L, "GSK_ERROR_BAD_KEYFILE_PASSWORD", "gsk_environment_init()", "GSKit", "DEFAULT.STH", "Key Database Password", "Bad keyfile password or password expired.");
        addGskCode(409L, "GSK_ERROR_BAD_KEY_LEN", "gsk_secure_soc_init()", "GSKit", "Cryptographic Key", "Key Parameter", "Invalid cryptographic key length.");
        addGskCode(410L, "GSK_ERROR_BAD_CERTIFICATE", "gsk_secure_soc_init()", "GSKit", "X.509 Certificate", "ASN.1 Parsing", "Certificate structure or ASN.1 encoding is invalid.");
        addGskCode(411L, "GSK_ERROR_BAD_CERT_SIG", "gsk_secure_soc_init()", "GSKit", "X.509 Signature", "Integrity Check", "Certificate signature verification failed.");
        addGskCode(412L, "GSK_ERROR_UNSUPPORTED_CERTIFICATE_TYPE", "gsk_secure_soc_init()", "GSKit", "Certificate Type", "Policy Error", "Certificate type is not supported by GSKit.");
        addGskCode(414L, "GSK_ERROR_NO_CIPHERS", "gsk_secure_soc_init()", "GSKit", "System Value QSSLCSL", "Cipher Negotiation", "No valid cipher suites available or configured in system value QSSLCSL.");
        addGskCode(415L, "GSK_ERROR_NO_CERTIFICATE", "gsk_secure_soc_init()", "GSKit", "Peer Certificate", "Client Auth", "No certificate was sent by the remote peer.");
        addGskCode(417L, "GSK_ERROR_BAD_PEER", "gsk_secure_soc_init()", "GSKit", "TLS Protocol Handshake", "Protocol Violation", "Remote peer sent an invalid TLS alert or handshake message.");
        addGskCode(420L, "GSK_ERROR_SOCKET_CLOSED", "gsk_secure_soc_read()", "GSKit", "TCP/IP Connection", "Connection State", "Secure socket connection was closed.");
        addGskCode(429L, "GSK_ERROR_NOT_SUPPORTED", "gsk_environment_init()", "GSKit", "GSKit Feature", "Configuration", "Requested TLS feature or protocol version is not supported.");
        addGskCode(501L, "GSK_CONFLICTING_VALIDATION_TYPES", "gsk_environment_init()", "GSKit", "Validation Settings", "Configuration", "Conflicting validation modes were enabled simultaneously.");
        addGskCode(6000L, "GSK_AS400_ERROR_NOT_TRUSTED", "gsk_secure_soc_init()", "GSKit", "Trust Store (DEFAULT.KDB)", "Trust Chain Verification", "Certificate Authority (CA) that signed the peer certificate is not trusted.", "WRKLNK OBJ('/QIBM/UserData/ICSS/Cert/Server/*')");
        addGskCode(6001L, "GSK_AS400_ERROR_BAD_CERTIFICATE", "gsk_secure_soc_init()", "GSKit", "IBM i X.509 Parser", "Certificate Format", "IBM i extended error: Malformed certificate presented.");
        addGskCode(6002L, "GSK_AS400_ERROR_NO_TEMPORARY_STORAGE", "gsk_environment_init()", "GSKit", "System Storage", "Resource Limit", "Temporary cryptographic storage exhausted on IBM i.");
        addGskCode(6003L, "GSK_AS400_ERROR_EXPIRED_CERTIFICATE", "gsk_secure_soc_init()", "GSKit", "Peer / Local Certificate", "Certificate Validity", "Certificate presented during handshake has expired.");
        addGskCode(6004L, "GSK_AS400_ERROR_NO_CERTIFICATE", "gsk_environment_init()", "GSKit", "DCM Application", "Certificate Assignment", "No certificate available for assignment.");
        addGskCode(6005L, "GSK_AS400_ERROR_CERTIFICATE_REVOKED", "gsk_secure_soc_init()", "GSKit", "CRL / OCSP Responder", "Revocation Check", "Certificate has been revoked according to CRL / OCSP.");
        addGskCode(6006L, "GSK_AS400_ERROR_NO_REVOCATION_STATUS", "gsk_secure_soc_init()", "GSKit", "CRL / OCSP Server", "Network Availability", "Revocation status could not be determined.");
        addGskCode(6007L, "GSK_AS400_ERROR_APPLICATION_NOT_REGISTERED", "gsk_environment_init()", "GSKit", "Registration Facility", "Application ID Lookup", "Application ID specified is not registered in Registration Facility (WRKREGINF).", "WRKREGINF");
        addGskCode(6008L, "GSK_AS400_ERROR_NO_KEYRING", "gsk_environment_init()", "GSKit", "Keyring Object", "IFS Path Resolution", "Keyring or certificate store not found.");
        addGskCode(6009L, "GSK_AS400_ERROR_INVALID_USAGE", "gsk_secure_soc_init()", "GSKit", "Certificate Extended Key Usage", "Key Usage Validation", "Certificate is not valid for the requested usage (e.g., server vs client authentication).");
        addGskCode(6010L, "GSK_AS400_ERROR_INVALID_USAGE_FOR_ENCRYPTED_SESSION", "gsk_secure_soc_init()", "GSKit", "Key Usage Field", "Session Encryption", "Certificate key usage does not permit session encryption.");
        addGskCode(6011L, "GSK_AS400_ERROR_BAD_CIPHER_SUITE", "gsk_secure_soc_init()", "GSKit", "System Value QSSLCSL", "Cipher Suite Negotiation", "No mutual cipher suite negotiated; check system value QSSLCSL.");
        addGskCode(6012L, "GSK_AS400_ERROR_TIMED_OUT", "gsk_secure_soc_init()", "GSKit", "TLS Handshake Timer", "Network Timeout", "TLS handshake operation timed out.");
        addGskCode(6013L, "GSK_AS400_ERROR_RENEGOTIATION_NOT_ALLOWED", "gsk_secure_soc_init()", "GSKit", "TLS Session State", "Renegotiation Policy", "Session renegotiation was requested but is disallowed by policy.");
        addGskCode(6014L, "GSK_AS400_ERROR_INVALID_ATTR", "gsk_environment_init()", "GSKit", "Environment Attributes", "Attribute ID", "Invalid GSKit environment attribute identifier.");
        addGskCode(6015L, "GSK_AS400_ERROR_INVALID_ATTR_VALUE", "gsk_environment_init()", "GSKit", "Environment Attributes", "Attribute Value", "Invalid GSKit attribute value provided.");
        addGskCode(6016L, "GSK_AS400_ERROR_NOT_SUPPORTED_FOR_SESSION", "gsk_secure_soc_init()", "GSKit", "Session Parameters", "Session Capability", "Option not supported for active session.");
        addGskCode(6017L, "GSK_AS400_ERROR_ALPN_NO_MATCH", "gsk_secure_soc_init()", "GSKit", "ALPN Protocols", "Protocol Negotiation", "Application-Layer Protocol Negotiation (ALPN) found no match.");
        addGskCode(6018L, "GSK_AS400_ERROR_CERT_VALIDATE", "gsk_secure_soc_init()", "GSKit", "Trust Store", "Validation Policy", "Certificate validation check failed.");
        addGskCode(6019L, "GSK_AS400_ERROR_NO_DEFAULT_CERT", "gsk_environment_init()", "GSKit", "WRKREGINF / *SYSTEM Store", "Certificate Assignment", "Application ID has no certificate assigned in Digital Certificate Manager (WRKREGINF).", "WRKREGINF");
        addGskCode(6020L, "GSK_AS400_ERROR_SESSION_TICKETS_NOT_SUPPORTED", "gsk_environment_init()", "GSKit", "TLS Session Tickets", "Protocol Feature", "TLS session tickets not supported.");
        addGskCode(6021L, "GSK_AS400_ERROR_EXTENDED_MASTER_SECRET_NOT_SUPPORTED", "gsk_environment_init()", "GSKit", "Extended Master Secret", "Extension Support", "Extended Master Secret extension not supported.");
    }

    private void addGskCode(long code, String constant, String originFunction, String serviceProgram, String targetObject, String failureDomain, String rootCause, String... cmds) {
        gsksslCodes.put(code, constant);
        gskDetails.put(code, new GskDetail(code, constant, originFunction, serviceProgram, targetObject, failureDomain, rootCause, cmds));
    }

    public Map<String, Object> decode(String query) {
        return search(query);
    }

    public Map<String, Object> search(String query) {
        if (query == null || query.trim().isEmpty()) {
            Map<String, Object> err = new HashMap<>();
            err.put("success", false);
            err.put("error", "Empty query");
            return err;
        }

        String trimmed = query.trim();

        // 1. Check if ADMIN3 log snippet
        if (trimmed.contains("SystemOut") || trimmed.contains("ProgramParameter") || trimmed.contains("qycu_") || (trimmed.toLowerCase().contains("function:") && trimmed.toLowerCase().contains("rc:"))) {
            return parseAdmin3Log(trimmed);
        }

        // 2. Check if numeric return code
        try {
            String cleanNum = trimmed.replaceAll("(?i)^RC:?\\s*", "");
            long rc = Long.parseLong(cleanNum);
            return searchGskCode(rc);
        } catch (NumberFormatException ignored) {
        }

        // 3. Keyword search across GSKSSL constants
        return searchKeyword(trimmed);
    }

    public Map<String, Object> searchGskCode(long code) {
        Map<String, Object> res = new HashMap<>();
        String constName = gsksslCodes.get(code);
        if (constName != null) {
            GskDetail d = gskDetails.get(code);
            res.put("success", true);
            res.put("isGskCode", true);
            res.put("rc", code);
            res.put("constant", constName);
            res.put("serviceProgram", d != null ? d.serviceProgram : "GSKit");
            res.put("originFunction", d != null ? d.originFunction : "gsk_*()");
            res.put("targetObject", d != null ? d.targetObject : "TLS Environment / Socket");
            res.put("failureDomain", d != null ? d.failureDomain : "TLS/SSL Subsystem");
            res.put("explanation", d != null ? d.rootCause : "Official GSKSSL return code " + code + " (" + constName + ").");
            res.put("recoveryCommands", d != null ? d.recoveryCommands : Collections.emptyList());
            return res;
        }

        res.put("success", false);
        res.put("isGskCode", true);
        res.put("rc", code);
        res.put("error", "Return code " + code + " not found in standard GSKSSL definitions.");
        return res;
    }

    public Map<String, Object> parseAdmin3Log(String logText) {
        Map<String, Object> res = new HashMap<>();
        res.put("isAdmin3Log", true);
        res.put("raw", logText);

        String[] lines = logText.split("\\r?\\n");
        String user = "N/A";
        String funcName = "N/A";
        Long rcVal = null;
        String job = "N/A";
        String actionFailure = "";
        List<Map<String, String>> parameters = new ArrayList<>();

        for (String line : lines) {
            // Match user
            Matcher uMatch = Pattern.compile("(?:^|\\s|/)user:\\s*([^\\s/]+)", Pattern.CASE_INSENSITIVE).matcher(line);
            if (uMatch.find()) user = uMatch.group(1);

            // Match function
            Matcher fMatch = Pattern.compile("(?:^|\\s|/)function:\\s*([^\\s/]+)", Pattern.CASE_INSENSITIVE).matcher(line);
            if (fMatch.find()) funcName = fMatch.group(1);

            // Match rc
            Matcher rMatch = Pattern.compile("(?:^|\\s|/)rc:\\s*(-?\\d+)", Pattern.CASE_INSENSITIVE).matcher(line);
            if (rMatch.find()) rcVal = Long.parseLong(rMatch.group(1));

            // Compact fallback "function / rc: N"
            if ("N/A".equals(funcName)) {
                Matcher compMatch = Pattern.compile("([a-zA-Z0-9_]+)\\s*/\\s*rc:\\s*(-?\\d+)", Pattern.CASE_INSENSITIVE).matcher(line);
                if (compMatch.find()) {
                    funcName = compMatch.group(1);
                    if (rcVal == null) rcVal = Long.parseLong(compMatch.group(2));
                }
            }

            // Job line
            Matcher jMatch = Pattern.compile("job:\\s*([^\\s\\r\\n]+)", Pattern.CASE_INSENSITIVE).matcher(line);
            if (jMatch.find()) job = jMatch.group(1);

            // Action failure
            Matcher aMatch = Pattern.compile("(CertificateAction\\.[^\\s:]+:\\s*API failed)", Pattern.CASE_INSENSITIVE).matcher(line);
            if (aMatch.find()) actionFailure = aMatch.group(1);

            // ProgramParameter extraction
            if (line.contains("ProgramParameter") || line.contains("input:") || line.contains("output:")) {
                String idx = String.valueOf(parameters.size());
                Matcher idxM = Pattern.compile("(\\d+)\\s*:\\s*ProgramParameter", Pattern.CASE_INSENSITIVE).matcher(line);
                if (idxM.find()) idx = idxM.group(1);

                String inputHex = "";
                Matcher inM = Pattern.compile("input:\\s*([0-9A-Fa-f]+)", Pattern.CASE_INSENSITIVE).matcher(line);
                if (inM.find()) inputHex = inM.group(1);

                String outLen = "0";
                Matcher lenM = Pattern.compile("output length:\\s*(\\d+)", Pattern.CASE_INSENSITIVE).matcher(line);
                if (lenM.find()) outLen = lenM.group(1);

                String outHex = "";
                Matcher outM = Pattern.compile("output:\\s*([0-9A-Fa-f]+)", Pattern.CASE_INSENSITIVE).matcher(line);
                if (outM.find()) outHex = outM.group(1);

                String decodedInput = decodeEbcdicHex(inputHex);
                String decodedOutput = decodeEbcdicHex(outHex);

                Map<String, String> p = new HashMap<>();
                p.put("index", idx);
                p.put("inputHex", inputHex);
                p.put("outLen", outLen);
                p.put("outHex", outHex);
                p.put("decodedInput", decodedInput);
                p.put("decodedOutput", decodedOutput);
                parameters.add(p);
            }
        }

        res.put("user", user);
        res.put("funcName", funcName);
        res.put("rc", rcVal);
        res.put("job", job);
        res.put("actionFailure", actionFailure);
        res.put("parameters", parameters);

        if (rcVal != null) {
            String constName = gsksslCodes.get(rcVal);
            GskDetail d = gskDetails.get(rcVal);
            res.put("constant", constName);
            res.put("detail", d);
            res.put("explanation", d != null ? d.rootCause : "API execution returned rc: " + rcVal);
        } else {
            res.put("explanation", "ADMIN3 log trace analyzed.");
        }

        res.put("success", true);
        return res;
    }

    public static String decodeEbcdicHex(String hexStr) {
        if (hexStr == null) return "";
        String clean = hexStr.replaceAll("\\s+", "");
        if (clean.length() < 2 || clean.length() % 2 != 0) return "";
        StringBuilder sb = new StringBuilder();
        int printable = 0;
        for (int i = 0; i < clean.length(); i += 2) {
            int byteVal = Integer.parseInt(clean.substring(i, i + 2), 16);
            if (byteVal == 0) continue; // null terminator
            int ascii = EBCDIC_CP037[byteVal];
            if (ascii >= 32 && ascii <= 126) {
                sb.append((char) ascii);
                printable++;
            } else if (byteVal >= 32 && byteVal <= 126) {
                sb.append((char) byteVal);
                printable++;
            }
        }
        if (printable == 0) return "";
        return sb.toString().trim();
    }

    private Map<String, Object> searchKeyword(String keyword) {
        Map<String, Object> res = new HashMap<>();
        List<Map<String, Object>> matches = new ArrayList<>();
        String lower = keyword.toLowerCase();

        for (Map.Entry<Long, String> entry : gsksslCodes.entrySet()) {
            if (entry.getValue().toLowerCase().contains(lower) || String.valueOf(entry.getKey()).equals(lower)) {
                Map<String, Object> m = new HashMap<>();
                m.put("code", entry.getKey());
                m.put("constant", entry.getValue());
                m.put("header", "/QIBM/include/gskssl.h");
                m.put("serviceProgram", "GSKit");
                matches.add(m);
            }
        }

        res.put("success", !matches.isEmpty());
        res.put("isKeywordSearch", true);
        res.put("query", keyword);
        res.put("matches", matches);
        return res;
    }
}

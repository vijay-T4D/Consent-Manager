package org.tsicoop.dpdpcms.framework;

/**
 * Format-preserving display masking for Data Principal identifiers
 * (email / mobile number / opaque IDs stored as `user_id` throughout the
 * schema — see 13_principal_pii_encryption.sql).
 *
 * This is deliberately NOT a method on {@link DbEncryption}: masking is pure
 * string formatting with no key dependency, whereas DbEncryption's static
 * initializer hard-fails the whole class if DB_ENCRYPTION_KEY isn't set.
 * Keeping this class independent means a masked value can always be
 * rendered even in a context that never touches the encryption key.
 *
 * Masking is applied only to identifiers being returned to someone who
 * didn't supply them (see callers in Consent.java/Grievance.java/
 * Compliance.java/Breach.java). It must NOT be applied when a principal is
 * viewing their own value (Principal.java rights portal, Wallet.java) or
 * when a value is simply being echoed back to the caller that sent it
 * (record_consent response).
 */
public class PiiMasking {

    private PiiMasking() {}

    /** Format-detecting dispatcher: routes to email/phone masking, or a generic fallback. */
    public static String mask(String value) {
        if (value == null || value.trim().isEmpty()) {
            return value;
        }
        String v = value.trim();
        if (v.indexOf('@') >= 0) {
            return maskEmail(v);
        }
        if (isPhoneShaped(v)) {
            return maskPhone(v);
        }
        return maskGeneric(v);
    }

    /** e.g. "vijay.rasquinha01@gmail.com" -> "v***1@g***.com" */
    public static String maskEmail(String email) {
        int at = email.indexOf('@');
        if (at < 0) {
            return maskGeneric(email);
        }
        String local = email.substring(0, at);
        String domain = email.substring(at + 1);

        String maskedLocal;
        if (local.length() <= 2) {
            maskedLocal = "*" + repeat("*", Math.max(1, local.length() - 1));
        } else {
            maskedLocal = local.charAt(0) + "***" + local.charAt(local.length() - 1);
        }

        String maskedDomain;
        int dot = domain.indexOf('.');
        if (dot > 0) {
            String label = domain.substring(0, dot);
            String tld = domain.substring(dot); // includes leading '.'
            maskedDomain = (label.length() > 0 ? label.charAt(0) : "") + "***" + tld;
        } else {
            maskedDomain = domain.length() > 0 ? (domain.charAt(0) + "***") : "***";
        }

        return maskedLocal + "@" + maskedDomain;
    }

    /** e.g. "+919876543210" -> "+91******3210"; "9876543210" -> "******3210" */
    public static String maskPhone(String phone) {
        String trimmed = phone.trim();
        String prefix = "";
        String digits = trimmed;
        if (trimmed.startsWith("+")) {
            // keep a short country-code-shaped prefix (+ and up to 2 digits), mask the rest
            int take = Math.min(3, trimmed.length()); // '+' + up to 2 digits
            prefix = trimmed.substring(0, take);
            digits = trimmed.substring(take);
        }
        if (digits.length() <= 4) {
            return prefix + repeat("*", digits.length());
        }
        String last4 = digits.substring(digits.length() - 4);
        int maskedLen = digits.length() - 4;
        return prefix + repeat("*", maskedLen) + last4;
    }

    /** Opaque token fallback, e.g. "anon_y5m299mnt5" -> "anon***t5" */
    private static String maskGeneric(String value) {
        if (value.length() <= 6) {
            return value.length() <= 2 ? repeat("*", value.length()) :
                    value.charAt(0) + "***" + value.charAt(value.length() - 1);
        }
        return value.substring(0, 4) + "***" + value.substring(value.length() - 2);
    }

    private static boolean isPhoneShaped(String v) {
        String candidate = v.startsWith("+") ? v.substring(1) : v;
        if (candidate.isEmpty()) {
            return false;
        }
        int digitCount = 0;
        for (int i = 0; i < candidate.length(); i++) {
            char c = candidate.charAt(i);
            if (Character.isDigit(c)) {
                digitCount++;
            } else if (c != ' ' && c != '-') {
                return false; // contains something other than digits/spaces/dashes -> not phone-shaped
            }
        }
        return digitCount >= 8;
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append(s);
        }
        return sb.toString();
    }
}

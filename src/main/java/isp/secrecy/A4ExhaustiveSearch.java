package isp.secrecy;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Arrays;

/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of th last three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would love to keep this text confidential Bob. Best, Alice.";
        System.out.println("[TOP SECRET] " + message);
        // Generation of weak key (5+3bytes)
        final byte[] keyBytes = new byte[8];
        keyBytes[5] = (byte) 0x12;
        keyBytes[6] = (byte) 0x34;
        keyBytes[7] = (byte) 0x56;
        final Key key = new SecretKeySpec(keyBytes, "DES");

        // encryption of the message with the weak key
        final Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        final byte[] cipherText = cipher.doFinal(message.getBytes());

        System.out.println("[CT] " + bytesToHex(cipherText));
        System.out.println("[ORIGINAL KEY] " + bytesToHex(keyBytes));
        System.out.println();
        System.out.println("brute force attack.");
        System.out.println("Searching through 2^24 = " + (256 * 256 * 256) + " possible keys");
        System.out.println();

        //brute force attack
        long startTime = System.currentTimeMillis();
        final byte[] recoveredKey = bruteForceKey(cipherText, message);
        long endTime = System.currentTimeMillis();

        if (recoveredKey != null) {
            System.out.println();
            System.out.println("[SUCCESS] Key found!");
            System.out.println("[RECOVERED KEY] " + bytesToHex(recoveredKey));
            System.out.println("[TIME] " + (endTime - startTime) + " ms");
            System.out.println("[KEYS MATCH] " + Arrays.equals(keyBytes, recoveredKey));
        } else {
            System.out.println("[FAIL] Key not found!");
        }
    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        final byte[] keyBytes = new byte[8];
        final Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        final byte[] expectedPlaintext = message.getBytes();

        int attemptCount = 0;

        //all possible values for byte 5
        for (int b5 = 0; b5 < 256; b5++) {
            keyBytes[5] = (byte) b5;
            //byte6
            for (int b6 = 0; b6 < 256; b6++) {
                keyBytes[6] = (byte) b6;
                //byte 7
                for (int b7 = 0; b7 < 256; b7++) {
                    keyBytes[7] = (byte) b7;
                    attemptCount++;
                    try {
                        // Create key and try decryption
                        final Key key = new SecretKeySpec(keyBytes, "DES");
                        cipher.init(Cipher.DECRYPT_MODE, key);
                        final byte[] decrypted = cipher.doFinal(ct);
                        // Check if decrypted matches message
                        if (Arrays.equals(decrypted, expectedPlaintext)) {
                            System.out.println("[ATTEMPT NUMBER] " + attemptCount);
                            return keyBytes.clone(); 
                        }
                    } catch (Exception e) {
                    }
                    // show progress every 1M attempts
                    if (attemptCount % 1000000 == 0) {
                        System.out.println("Tried " + attemptCount + " keys... Current: " +
                                String.format("%02X %02X %02X", b5 & 0xFF, b6 & 0xFF, b7 & 0xFF));
                    }
                }
            }
        }
        return null; 
    }

    // byte to hex conversion
    private static String bytesToHex(byte[] bytes) {
        StringBuilder b2h = new StringBuilder();
        for (byte b : bytes) {b2h.append(String.format("%02X", b & 0xFF));}
        return b2h.toString();
    }
}

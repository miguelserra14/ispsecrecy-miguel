package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;

import java.security.Key;
import java.security.SecureRandom;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                //final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Recall, ChaCha2 requires that you specify the nonce and the counter explicitly.
                 */
                final SecureRandom random = new SecureRandom();
                for (int i = 1; i <= 10; i++) {
                    // Create message and nonce
                    final String message = "I love you Bob. Message #" + i + ". Until next time, Alice.";
                    final byte[] nonce = new byte[12];
                    random.nextBytes(nonce);

                    // chacha20 parameter spec with nonce and counter (starts at 1)
                    final ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, 1);

                    // Initialize cipher
                    final Cipher cipher = Cipher.getInstance("ChaCha20");
                    cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

                    // Encrypt the message
                    final byte[] cipherText = cipher.doFinal(message.getBytes());

                    //nonce is sent first and then the encrypted message
                    send("bob", nonce);
                    send("bob", cipherText);
                    print("Sent message #%d to Bob: %s", i, message);

                    //Bob's reply
                    final byte[] bobNonce = receive("bob");
                    final byte[] bobCipherText = receive("bob");

                    // Decrypt Bob's reply using his nonce
                    final ChaCha20ParameterSpec bobParamSpec = new ChaCha20ParameterSpec(bobNonce, 1);
                    cipher.init(Cipher.DECRYPT_MODE, key, bobParamSpec);
                    final byte[] bobPlainText = cipher.doFinal(bobCipherText);

                    print("reply #%d from Bob: %s", i, new String(bobPlainText));
                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final SecureRandom random = new SecureRandom();

                for (int i = 1; i <= 10; i++) {
                    // Receive nonce and encrypted message
                    final byte[] nonce = receive("alice");
                    final byte[] cipherText = receive("alice");

                    // chacha20 parameter spec with received nonce and counter
                    final ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, 1);

                    // Initialize cipher for decryption
                    final Cipher cipher = Cipher.getInstance("ChaCha20");
                    cipher.init(Cipher.DECRYPT_MODE, key, paramSpec);

                    // Decrypt the message
                    final byte[] plainText = cipher.doFinal(cipherText);
                    final String message = new String(plainText);
                    print("Received message #%d from Alice: %s", i, message);

                    // Create and send reply
                    final String reply = "I love you too Alice. Reply #" + i + ". Love, Bob.";

                    // Generate new nonce for the reply
                    final byte[] replyNonce = new byte[12];
                    random.nextBytes(replyNonce);
                    // parameter spec for reply
                    final ChaCha20ParameterSpec replyParamSpec = new ChaCha20ParameterSpec(replyNonce, 1);

                    // Encrypt reply
                    cipher.init(Cipher.ENCRYPT_MODE, key, replyParamSpec);
                    final byte[] replyCipherText = cipher.doFinal(reply.getBytes());

                    // Send nonce and encrypted reply
                    send("alice", replyNonce);
                    send("alice", replyCipherText);
                    print("Sent reply #%d to Alice: %s", i, reply);
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}

package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import java.security.Key;

/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using a
 * AES in counter mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AESInCTRMode {
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
                 for (int n = 1; n <= 10; n++) {
                    final String message = "I love you Bob. Message #" + n + ". Until next time, Alice.";
                    final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                    aes.init(Cipher.ENCRYPT_MODE, key);

                    // Encript the message
                    final byte[] cipherText = aes.doFinal(message.getBytes());
                    // Get the IV used for encryption
                    final byte[] iv = aes.getIV();

                    // Send IV and then the encrypted message to bob
                    send("bob", iv);
                    send("bob", cipherText);
                    print("Message #%d to Bob has been sent: %s", n, message);

                    // Receive bobs reply
                    final byte[] bobIv = receive("bob");
                    final byte[] bobCipherText = receive("bob");

                    // Decrypt bobs reply
                    final IvParameterSpec bobIvSpec = new IvParameterSpec(bobIv);
                    aes.init(Cipher.DECRYPT_MODE, key, bobIvSpec);
                    final byte[] bobPlainText = aes.doFinal(bobCipherText);

                    print("Reply #%d from Bob has been received: %s", n, new String(bobPlainText));
                }
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 */
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /* TODO STEP 4
                 * Bob receives, decrypts and displays a message.
                 * Once you obtain the byte[] representation of cipher parameters,
                 * you can load them with:
                 *
                 *   IvParameterSpec ivSpec = new IvParameterSpec(iv);
                 *   aes.init(Cipher.DECRYPT_MODE, my_key, ivSpec);
                 *
                 * You then pass this object to the cipher init() method call.*
                 */
                 for (int i = 1; i <= 10; i++) {
                    // Receive IV and then encrypted message from Alice
                    final byte[] iv = receive("alice");
                    final byte[] cipherText = receive("alice");

                    // cipher for decryption with the receivedIV
                    final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                    final IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    aes.init(Cipher.DECRYPT_MODE, key, ivSpec);

                    // Decrypt the message
                    final byte[] plainText = aes.doFinal(cipherText);
                    final String message = new String(plainText);
                    print("message #%d from Alice has been received: %s", i, message);

                    // write and send reply to Alice
                    final String reply = "I love you too Alice. Reply #" + i + ". XOXO, Bob.";

                    // Encrypt reply (new IV will be generated)
                    aes.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] replyCipherText = aes.doFinal(reply.getBytes());
                    final byte[] replyIv = aes.getIV();

                    // Send IV and encrypted reply
                    send("alice", replyIv);
                    send("alice", replyCipherText);

                    print("reply #%d to Alice has been sent: %s", i, reply);
                }
                
                
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}

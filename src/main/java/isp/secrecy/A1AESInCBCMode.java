package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import java.security.Key;

/**
 * TASK:
 * ver os files de agent communicatione symmetric cypher e ver como se encaixam no projeto e como funcionam
 * dps de ter isso sabido ver como e que este se encaixa e resolve lo 
 * ler a documentação e todos os links anexados nos files
 * 
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * AES in CBC mode. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AESInCBCMode {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("AES").generateKey();
       

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "I love you Bob. Kisses, Alice.";
                /* TODO STEP 3:
                 * Alice creates, encrypts and sends a message to Bob. Bob replies to the message.
                 * Such exchange repeats 10 times.
                 *
                 * Do not forget: In CBC (and CTR mode), you have to also
                 * send the IV. The IV can be accessed via the
                 * cipher.getIV() call
                 
                for (int i = 0; i < 10; i++) {
                    // prepare cipher for encryption (new IV is generated on init)
                    final javax.crypto.Cipher enc = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding (128)");
                    enc.init(javax.crypto.Cipher.ENCRYPT_MODE, key);

                    final String outMsg = message;
                    final byte[] ct = enc.doFinal(outMsg.getBytes());
                    final byte[] iv = enc.getIV();

                    // send IV then ciphertext to Bob
                    send("bob", iv);
                    send("bob", ct);

                    System.out.println("alice -> bob (ciphertext, base64): " +
                            java.util.Base64.getEncoder().encodeToString(ct));

                    // receive Bob's reply: IV then ciphertext
                    final byte[] replyIv = (byte[]) receive("bob");
                    final byte[] replyCt = (byte[]) receive("bob");

                    // decrypt Bob's reply
                    final javax.crypto.Cipher dec = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
                    dec.init(javax.crypto.Cipher.DECRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(replyIv));
                    final byte[] replyPt = dec.doFinal(replyCt);

                    System.out.println("alice received: " + new String(replyPt));
                }*/
                
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
                 * for (int i = 0; i < 10; i++) {
                    // receive IV then ciphertext from Alice
                    final byte[] iv = (byte[]) receive("alice");
                    final byte[] ct = (byte[]) receive("alice");

                    // decrypt Alice's message
                    final javax.crypto.Cipher dec = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
                    dec.init(javax.crypto.Cipher.DECRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(iv));
                    final byte[] pt = dec.doFinal(ct);

                    System.out.println("bob received: " + new String(pt));

                    // prepare reply
                    final String reply = "I love you Alice. Kisses, Bob. (msg #" + (i + 1) + ")";

                    // encrypt reply (new IV is generated on init)
                    final javax.crypto.Cipher enc = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
                    enc.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
                    final byte[] replyCt = enc.doFinal(reply.getBytes());
                    final byte[] replyIv = enc.getIV();

                    // send IV then ciphertext back to Alice
                    send("alice", replyIv);
                    send("alice", replyCt);

                    System.out.println("bob -> alice (ciphertext, base64): " +
                            java.util.Base64.getEncoder().encodeToString(replyCt));
                }
                 */
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}

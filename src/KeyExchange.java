import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

public class KeyExchange {
  private static BigInteger g512 = new BigInteger("1234567890", 16);

  private static BigInteger p512 = new BigInteger("1234567890", 16);

  public static void main(String[] args) throws Exception {
    //Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    DHParameterSpec dhParams = new DHParameterSpec(p512, g512);
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");

    keyGen.initialize(dhParams, new SecureRandom());

    KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
    KeyPair aPair = keyGen.generateKeyPair();
    KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");
    KeyPair bPair = keyGen.generateKeyPair();

    aKeyAgree.init(aPair.getPrivate());
    bKeyAgree.init(bPair.getPrivate());

    aKeyAgree.doPhase(bPair.getPublic(), true);
    bKeyAgree.doPhase(aPair.getPublic(), true);

    MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
    System.out.println(new String(hash.digest(aKeyAgree.generateSecret())));
    System.out.println(new String(hash.digest(bKeyAgree.generateSecret())));
  }
}
/*
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;

import javax.crypto.spec.DHParameterSpec;

public class Main {
  public static void main(String[] argv) throws Exception {
    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
    paramGen.init(1024);

    AlgorithmParameters params = paramGen.generateParameters();
    DHParameterSpec dhSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);

    System.out.println("" + dhSpec.getP() + "," + dhSpec.getG() + "," + dhSpec.getL());
  }
}*/
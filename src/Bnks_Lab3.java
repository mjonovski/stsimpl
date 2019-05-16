/*
* To change this license header, choose License Headers in Project Properties.
* To change this template file, choose Tools | Templates
* and open the template in the editor.
*/

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import javax.annotation.Resource;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.ws.Provider;
import javax.xml.ws.Service;
import javax.xml.ws.ServiceMode;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.WebServiceProvider;
import javax.xml.transform.Source;
import javax.xml.ws.handler.MessageContext;

/**
 *
 * @author Renata
 */
public class Bnks_Lab3 {

	/**
	 * @param args
	 *            the command line arguments
	 */

	public static class AES {
		static String IV = "AAAAAAAAAAAAAAAA";

		public AES() {

		}

		public byte[] encrypt(String plainText, String encryptionKey) throws Exception {

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
			SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
			return cipher.doFinal(plainText.getBytes("UTF-8"));
		}

		public String decrypt(byte[] cipherText, String encryptionKey) throws Exception {
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
			SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
			return new String(cipher.doFinal(cipherText), "UTF-8");
		}
	}

	public static class RSA {
		private BigInteger n, d, e;

		private int bitlen = 1024;

		/**
		 * Create an instance that can encrypt using someone elses public key.
		 */
		public RSA(BigInteger newn, BigInteger newe) {
			n = newn;
			e = newe;
		}

		/** Create an instance that can both encrypt and decrypt. */
		public RSA(int bits) {
			bitlen = bits;
			SecureRandom r = new SecureRandom();
			BigInteger p = new BigInteger(bitlen / 2, 100, r);
			BigInteger q = new BigInteger(bitlen / 2, 100, r);
			n = p.multiply(q);
			BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
			e = new BigInteger("3");
			while (m.gcd(e).intValue() > 1) {
				e = e.add(new BigInteger("2"));
			}
			d = e.modInverse(m);
		}

		/** Encrypt the given plaintext message. */
		public synchronized String encrypt(String message) {
			return (new BigInteger(message.getBytes())).modPow(e, n).toString();
		}

		/** Encrypt the given plaintext message. */
		public synchronized BigInteger encrypt(BigInteger message) {
			return message.modPow(e, n);
		}

		/** Decrypt the given ciphertext message. */
		public synchronized String decrypt(String message) {
			return new String((new BigInteger(message)).modPow(d, n).toByteArray());
		}

		/** Decrypt the given ciphertext message. */
		public synchronized BigInteger decrypt(BigInteger message) {
			return message.modPow(d, n);
		}

		/** Generate a new public and private key set. */
		public synchronized void generateKeys() {
			SecureRandom r = new SecureRandom();
			BigInteger p = new BigInteger(bitlen / 2, 100, r);
			BigInteger q = new BigInteger(bitlen / 2, 100, r);
			n = p.multiply(q);
			BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
			e = new BigInteger("3");
			while (m.gcd(e).intValue() > 1) {
				e = e.add(new BigInteger("2"));
			}
			d = e.modInverse(m);
		}

		/** Return the modulus. */
		public synchronized BigInteger getN() {
			return n;
		}

		public synchronized BigInteger getD() {
			return d;
		}

		/** Return the public key. */
		public synchronized BigInteger getE() {
			return e;
		}
	}

	public static class Korisnik {

		int alfa = 7919;
		int publicKey;
		String sentMsg1;
		String sentMsg2;
		String reciveMsg1;
		String reciveMsg2;

		public Korisnik() {

		}

		public int randomStepen() {
			int num = 0;
			Random rand = new Random(); // generate a random number
			num = rand.nextInt(1000) + 1;

			while (!isPrime(num)) {
				num = rand.nextInt(1000) + 1;
			}
			return num; // print the number
		}

		/**
		 * Checks to see if the requested value is prime.
		 */
		private static boolean isPrime(int inputNum) {
			if (inputNum <= 3 || inputNum % 2 == 0)
				return inputNum == 2 || inputNum == 3; // this returns false if
														// number is <=1 & true
														// if number = 2 or 3
			int divisor = 3;
			while ((divisor <= Math.sqrt(inputNum)) && (inputNum % divisor != 0))
				divisor += 2; // iterates through all possible divisors
			return inputNum % divisor != 0; // returns true/false
		}

		public int generateKey(int x, int y) {
			int key;
			key = (int) Math.pow(alfa, (x * y));
			return key;
		}

	}

	public static void STS(Korisnik a, Korisnik b) throws Exception {
		// prv chekor prakjanje od A kon B alfa^x
		int x = a.randomStepen();
		a.sentMsg1 = Double.toString(Math.pow(a.alfa, x));
		b.reciveMsg1 = Double.toString(Math.pow(a.alfa, x));

		// vtor chekor prakjanje od B kon A (alfa^y, EK(SB(gy, gx)))
		int y = b.randomStepen();
		b.sentMsg1 = Double.toString(Math.pow(a.alfa, y));
		a.reciveMsg1 = Double.toString(Math.pow(a.alfa, y));

		// potpisuvanje so potpisot na b na (alfa^y,alfa^x)
		RSA rsa = new RSA(1024);
		String plainText = b.sentMsg1 + a.sentMsg1;
		String Sb = rsa.encrypt(plainText);
		System.out.println(Sb);
		// enkriptiranje na potpisot so key i prakjanje kako vtora poraka na a
		int k = b.generateKey(x, y);
		String key = (Integer.toString(k));
		System.out.println(key);
		AES aes = new AES();
		b.sentMsg2 = Arrays.toString(aes.encrypt(Sb, key));

		a.reciveMsg2 = b.sentMsg2;
		// dekriptira i proveruva kluucot na b
		String Sb1 = aes.decrypt((a.reciveMsg2).getBytes(), key);
		rsa.decrypt(Sb1);
		System.out.println(Sb1);
		// potpisuvanje so potpisot na a na (alfa^x,alfa^y)
		String plainText1 = a.sentMsg1 + b.sentMsg1;
		String Sa = rsa.encrypt(plainText1);
		// enkriptiranje na potpisot so key i prakjanje na b
		a.sentMsg1 = Arrays.toString(aes.encrypt(Sa, key));
		b.reciveMsg1 = a.sentMsg1;

	}

	public static void main(String[] args) throws Exception {
		// TODO code application logic here
		Korisnik a = new Korisnik();
		Korisnik b = new Korisnik();
		STS(a, b);
	}

}
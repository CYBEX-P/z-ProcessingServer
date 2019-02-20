/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cybexprocessing;

import com.mongodb.BasicDBObject;
import com.mongodb.Block;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.Mongo;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import com.mongodb.MongoException;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.gridfs.GridFSBucket;
import com.mongodb.client.gridfs.GridFSBuckets;
import com.mongodb.gridfs.GridFS;
import java.io.*;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import org.bson.types.ObjectId;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.gridfs.GridFSDownloadStream;
import com.mongodb.client.gridfs.model.GridFSFile;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bson.Document;

/**
 * Utility class for encrypting/decrypting files.
 *
 * @author Michael Lones
 */
public class CybexProcessing {

    public static final int AES_Key_Size = 128;

    Cipher pkCipher, aesCipher;
    byte[] aesKey;
    SecretKeySpec aeskeySpec;

    /**
     * Constructor: creates ciphers
     */
    public CybexProcessing() throws GeneralSecurityException {
        // create RSA public key cipher
        pkCipher = Cipher.getInstance("RSA");
        // create AES shared key cipher
        aesCipher = Cipher.getInstance("AES");
    }

    /**
     * Creates a new AES key
     */
    public void makeKey() throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(AES_Key_Size);
        SecretKey key = kgen.generateKey();
        aesKey = key.getEncoded();
        aeskeySpec = new SecretKeySpec(aesKey, "AES");
    }

    /**
     * Decrypts an AES key from a file using an RSA private key
     */
    public void loadKey(File in, File privateKeyFile) throws GeneralSecurityException, IOException {
        // read private key to be used to decrypt the AES key
        byte[] encodedKey = new byte[(int) privateKeyFile.length()];
        new FileInputStream(privateKeyFile).read(encodedKey);

        // create private key
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pk = kf.generatePrivate(privateKeySpec);

        // read AES key
        pkCipher.init(Cipher.DECRYPT_MODE, pk);
        aesKey = new byte[AES_Key_Size / 8];
        CipherInputStream is = new CipherInputStream(new FileInputStream(in), pkCipher);
        is.read(aesKey);
        aeskeySpec = new SecretKeySpec(aesKey, "AES");
    }

    /**
     * Encrypts the AES key to a file using an RSA public key
     */
    public void saveKey(File out, File publicKeyFile) throws IOException, GeneralSecurityException {
        // read public key to be used to encrypt the AES key
        byte[] encodedKey = new byte[(int) publicKeyFile.length()];
        new FileInputStream(publicKeyFile).read(encodedKey);

        // create public key
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pk = kf.generatePublic(publicKeySpec);

        // write AES key
        pkCipher.init(Cipher.ENCRYPT_MODE, pk);
        CipherOutputStream os = new CipherOutputStream(new FileOutputStream(out), pkCipher);
        os.write(aesKey);
        os.close();
    }

    /**
     * Encrypts and then copies the contents of a given file.
     */
    public void encrypt(File in, File out) throws IOException, InvalidKeyException {
        aesCipher.init(Cipher.ENCRYPT_MODE, aeskeySpec);

        FileInputStream is = new FileInputStream(in);
        CipherOutputStream os = new CipherOutputStream(new FileOutputStream(out), aesCipher);

        copy(is, os);

        os.close();
    }

    /**
     * Decrypts and then copies the contents of a given file.
     */
    public void decrypt(File in, File out) throws IOException, InvalidKeyException {
        aesCipher.init(Cipher.DECRYPT_MODE, aeskeySpec);

        CipherInputStream is = new CipherInputStream(new FileInputStream(in), aesCipher);
        FileOutputStream os = new FileOutputStream(out);

        copy(is, os);

        is.close();
        os.close();
    }

    public String decryptToString(File in) throws IOException, InvalidKeyException {
        aesCipher.init(Cipher.DECRYPT_MODE, aeskeySpec);

        CipherInputStream is = new CipherInputStream(new FileInputStream(in), aesCipher);

        StringBuilder stringBuilder = new StringBuilder();
        String line = null;

        try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(is, "UTF-8"))) {
            while ((line = bufferedReader.readLine()) != null) {
                stringBuilder.append(line);
            }
        }

        is.close();
        return stringBuilder.toString();

    }

    /**
     * Copies a stream.
     */
    private void copy(InputStream is, OutputStream os) throws IOException {
        int i;
        byte[] b = new byte[1024];
        while ((i = is.read(b)) != -1) {
            os.write(b, 0, i);
        }
    }

    public void writeToDB(String s,String CollectionName,String DBName) throws Exception {
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        
        MongoClient mongo = new MongoClient(new MongoClientURI("mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/"+DBName+"?authSource=admin"));
        DB db = mongo.getDB(DBName);
        DBCollection table = db.getCollection(CollectionName);
        
        /*
        SecretKey skey = new SecretKeySpec("1234567890987654".getBytes(), "AES");
        Cipher AESCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        AESCipher.init(Cipher.ENCRYPT_MODE, skey);

        byte[] byteCipherText = AESCipher.doFinal(s.getBytes());
        String ss=new String(byteCipherText);
        System.out.println("Ciphered text : " + ss);
        BasicDBObject encryptedDoc = new BasicDBObject();
        encryptedDoc.put("EncryptedSTIX", new String(byteCipherText));*/
         BasicDBObject encryptedDoc = new BasicDBObject();
         encryptedDoc.put("EncryptedSTIX", s);
        
        table.insert(encryptedDoc);
        
        
        mongo = new MongoClient(new MongoClientURI("mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/report_db?authSource=admin"));
        db = mongo.getDB("report_db");
        table = db.getCollection(CollectionName);
        /*skey = new SecretKeySpec("1234567890987654".getBytes(), "AES");
        //IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
        AESCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        AESCipher.init(Cipher.DECRYPT_MODE, skey);
        byte[] decryptedText=AESCipher.doFinal(byteCipherText);
        ss=new String(decryptedText);
        System.out.println("Deciphered text : " + ss);
        
        */
        //BasicDBObject decryptedDoc = new BasicDBObject();
        //decryptedDoc.put (dbObj);
        //Document decryptedDoc=Document.parse(ss);
            //Object o = com.mongodb.util.JSON.parse(ss);
        Object o = com.mongodb.util.JSON.parse(s);
        DBObject dbObj = (DBObject) o;
        //table.insert((List<? extends DBObject>) decryptedDoc);
        table.insert(dbObj);
        

    }
    

    public String readFileFromMongoDB(MongoClient mongoClient, MongoClientURI uri, DB mobgoDB,
        DBCollection mongoCol, ObjectId oi,String typtag,String timezone,String uuid) throws FileNotFoundException, IOException {
        String databaseS=uri.getDatabase();
        MongoDatabase db = mongoClient.getDatabase(databaseS);
        //System.out.println("uri db = "+uri.getDatabase());
        GridFSBucket gridFSBucket = GridFSBuckets.create(db);

        GridFSDownloadStream downloadStream = gridFSBucket.openDownloadStream(oi);
        int fileLength = (int) downloadStream.getGridFSFile().getLength();
        byte[] bytesToWriteTo = new byte[fileLength];
        downloadStream.read(bytesToWriteTo);
        downloadStream.close();
        System.out.println("Length = " + fileLength);
        //System.out.println("Length = " + fileLength + " "+new String(bytesToWriteTo));

        FileOutputStream stream = new FileOutputStream("/Users/Xalid/Desktop/temEncr.txt");
        try {
            stream.write(bytesToWriteTo);
        } finally {
            stream.close();
        }

        String[] cmd = {
            "/usr/local/opt/python/libexec/bin/python",
            "/Users/Xalid/NetBeansProjects/decrypt.py",
            "/Users/Xalid/Desktop/temEncr.txt",};

        Process p = Runtime.getRuntime().exec(cmd);

        BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
        BufferedReader stdError = new BufferedReader(new InputStreamReader(p.getErrorStream()));
        String s = null;
        String output = null;
        while ((s = stdInput.readLine()) != null) {
            System.out.println(s);
            // System.out.println("testtt");
            output = s;
            String newline = System.getProperty("line.separator");
            String[] lines = output.split("\n");
            for (int i = 0; i < lines.length; i++) {
                System.out.println("Output: " + i + " " + lines[i]);
                String[] cmd2 = {
                    "/usr/local/opt/python/libexec/bin/python",
                    //"/Users/Xalid/NetBeansProjects/parsemain.py",
                    "/Users/Xalid/Downloads/FOR_KHALID/parsemain.py",
                    lines[i],
                    "339522a4-9f1c-47f9-a252-d47e09f31d5a",
                    typtag, 
                    timezone,
                };
                
                Process p2 = Runtime.getRuntime().exec(cmd2);
                BufferedReader stdInput2 = new BufferedReader(new InputStreamReader(p2.getInputStream()));
                BufferedReader stdError2 = new BufferedReader(new InputStreamReader(p2.getErrorStream()));
                String s2 = null;
                StringBuilder output2 = new StringBuilder();
                while ((s2 = stdInput2.readLine()) != null) {
                    System.out.println(s2);
                    // System.out.println("testtt");
                    output2.append(s2);
                   // output2.append("\n");
                    
                }
                while ((s2 = stdError2.readLine()) != null) {
                    System.out.println(s2);
                    //output2 = s2;
                }

                try {
                    System.out.println("Stix = "+output2.toString());
                    writeToDB(output2.toString(),"events","archive_db");
                    } catch (Exception ex) {
                    System.out.println("Exception ="+ex.getMessage());
                    }
                    /*String[] cmd3 = {
                    "/usr/local/opt/python/libexec/bin/python",
                    "/Users/Xalid/NetBeansProjects/encrypt_aes.py",
                    output2,};
                    
                    
                    
                    Process p3 = Runtime.getRuntime().exec(cmd3);
                    
                    File file = new File("aes_encrypted_file"); // this is python encrypt_aes.py output
                    byte[] resultb = null;
                    ByteArrayOutputStream result = null;
                    try {
                    InputStream input = new BufferedInputStream(new FileInputStream(file));
                    byte[] bucket = new byte[32 * 1024];
                    try {
                    try {
                    //Use buffering? No. Buffering avoids costly access to disk or network;
                    //buffering to an in-memory stream makes no sense.
                    result = new ByteArrayOutputStream(bucket.length);
                    int bytesRead = 0;
                    while (bytesRead != -1) {
                    //aInput.read() returns -1, 0, or more :
                    bytesRead = input.read(bucket);
                    if (bytesRead > 0) {
                    result.write(bucket, 0, bytesRead);
                    }
                    }
                    } finally {
                    input.close();
                    //result.close(); this is a no-operation for ByteArrayOutputStream
                    }
                    } catch (IOException ex) {
                        
                    }
                    resultb=result.toByteArray();
                    DBCollection table = mobgoDB.getCollection("archive_db");
                    BasicDBObject encryptedDoc = new BasicDBObject();
                    encryptedDoc.put("EncryptedSTIX", new String(resultb));
                    table.insert(encryptedDoc);
                    
                    } catch (FileNotFoundException ex) {
                    
                    }*/
                

            }

        }

        //  while ((s = stdError.readLine()) != null) {
        //    System.out.println(s);
        //    output = s;
        // }
        File file = new File("/Users/Xalid/Desktop/temEncr.txt");
        file.delete();
        return "";
    }

    public DBCursor findDataInDB(MongoClient mongoClient, DB mobgoDB, DBCollection mongoCol, String field, boolean value) {
        BasicDBObject whereQuery = new BasicDBObject();
        whereQuery.put(field, value);
        DBCursor cursor = mongoCol.find(whereQuery);
        return cursor;
    }

    public void getNewFiles() throws Exception {
        MongoClientURI uri = new MongoClientURI("mongodb://cybexp_user:CybExP_777@134.197.21.231:27017/cache_db?authSource=admin");
        MongoClient mongo = new MongoClient(uri);
        //DB db = mongo.getDB("db_1");
        DB db = mongo.getDB("cache_db");
        DBCollection table = db.getCollection("file_entries");
        //DBCollection archive= db.getCollection("archive");

        while (true) {
            DBCursor foundOne = findDataInDB(mongo, db, table, "processed", false);
            while (foundOne.hasNext()) {
                try {
                    //System.out.println("Found:" + foundOne.toString());
                    DBObject doc1 = foundOne.next();
                    ObjectId objID = (ObjectId) doc1.get("fid");
                    String typetag = doc1.get("typtag").toString();
                    String timezone = doc1.get("timezone").toString();
                    String uuid="test";//(String) doc1.get("orgid");
                    
                    //System.out.println("fid=" + objID);

                    readFileFromMongoDB(mongo, uri, db, table, objID,typetag,timezone,uuid);

                    setStatusOfObjectToOne(mongo, db, table, doc1);

                    //System.out.println("Status updated to 1");
                } catch (MongoException ex) {
                    System.out.println(ex.getMessage());
                }
            }

            TimeUnit.SECONDS.sleep(10);
        }

    }

    public int setStatusOfObjectToOne(MongoClient mongoClient, DB mobgoDB,
            DBCollection mongoCol, DBObject doc1) {
        mongoCol.update(doc1, new BasicDBObject("$set", new BasicDBObject(
                "processed", true)));
        return 1;
    }

    public static void main(String[] args) throws Exception {
        CybexProcessing cp = new CybexProcessing();

        //cp.makeKey();
        //cp.saveKey(new File("/Users/Xalid/KeyPair/symmetric.der"),new File("/Users/Xalid/KeyPair/public.der"));
        //cp.loadKey(new File("/Users/Xalid/KeyPair/symmetric.der"), new File("/Users/Xalid/KeyPair/private.der"));
        //cp.encrypt(new File("/Users/Xalid/KeyPair/Text.txt"), new File("/Users/Xalid/KeyPair/EncryptedText2.txt"));
        // cp.decrypt(new File("/Users/Xalid/KeyPair/EncryptedText.txt"), new File("/Users/Xalid/KeyPair/Text2.txt"));
        // String decryptedFileString = cp.decryptToString(new File("/Users/Xalid/KeyPair/EncryptedText.txt"));
        //ObjectId oi=new ObjectId("5bad71062358dd16481de35e");
        try {
            cp.getNewFiles();
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        //String encryptedFileFromMongoDB= cp.readFileFromMongoDB(oi);
        /*  
        String[] cmd = {
            "python",
            "/Users/Xalid/NetBeansProjects/samplePython.py",
            decryptedFileString,};

        Process p = Runtime.getRuntime().exec(cmd);

        BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
        BufferedReader stdError = new BufferedReader(new InputStreamReader(p.getErrorStream()));
        String s = null;
        String output=null;
        while ((s = stdInput.readLine()) != null) {
            System.out.println(s);
            output=s;
        }
        while ((s = stdError.readLine()) != null) {
            System.out.println(s);
            output=s;
        }
        cp.writeToDB(output);
         */

// to decrypt it again
        //cp.loadKey(encryptedKeyFile, privateKeyFile);
        //cp.decrypt(encryptedFile, unencryptedFile);
    }
}
/*
Usage
To use the code, you need corresponding public and private RSA keys. RSA keys can be generated using the open source tool OpenSSL. However, you have to be careful to generate them in the format required by the Java encryption libraries. To generate a private key of length 2048 bits:

openssl genrsa -out private.pem 2048
To get it into the required (PKCS#8, DER) format:

openssl pkcs8 -topk8 -in private.pem -outform DER -out private.der -nocrypt
To generate a public key from the private key:

openssl rsa -in private.pem -pubout -outform DER -out public.der
 */

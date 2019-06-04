/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package power_analysis_applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 *
 * @author Martin
 */
public class PowerAnalysisApplet extends javacard.framework.Applet {
    final static byte CLA_THIS_APPLET = (byte) 0xB0;

    final static byte INS_PREPARE_GENERATE_RNGS             = (byte) 0xA0;
    final static byte INS_GENERATE_RNGS                     = (byte) 0xB0;
    final static byte INS_PREPARE_AES256_SET_KEY            = (byte) 0xA1;
    final static byte INS_AES256_SET_KEY                    = (byte) 0xB1;
    final static byte INS_PREPARE_3DES_SET_KEY              = (byte) 0xA2;
    final static byte INS_3DES_SET_KEY                      = (byte) 0xB2;
    final static byte INS_PREPARE_AES256_ENCRYPT            = (byte) 0xA3;
    final static byte INS_AES256_ENCRYPT                    = (byte) 0xB3;
    final static byte INS_PREPARE_3DES_ENCRYPT              = (byte) 0xA4;
    final static byte INS_3DES_ENCRYPT                      = (byte) 0xB4;    
    final static byte INS_PREPARE_SHA1_MESSAGE_DIGEST       = (byte) 0xA5;
    final static byte INS_SHA1_MESSAGE_DIGEST               = (byte) 0xB5;
    final static byte INS_PREPARE_SHA256_MESSAGE_DIGEST     = (byte) 0xA6;
    final static byte INS_SHA256_MESSAGE_DIGEST             = (byte) 0xB6;
    final static byte INS_PREPARE_GENERATE_RSA512_KEY_PAIR  = (byte) 0xA7;
    final static byte INS_GENERATE_RSA512_KEY               = (byte) 0xB7;
    final static byte INS_PREPARE_SIGN_WITH_RSA512          = (byte) 0xA8;
    final static byte INS_SIGN_WITH_RSA512                  = (byte) 0xB8;
    final static byte INS_PREPARE_GENERATE_EC192FP_KEY_PAIR = (byte) 0xA9;    
    final static byte INS_GENERATE_EC192FP_KEY              = (byte) 0xB9;
    final static byte INS_PREPARE_SIGN_WITH_EC192FP         = (byte) 0xAA;
    final static byte INS_SIGN_WITH_EC192FP                 = (byte) 0xBA;
    final static byte INS_PREPARE_GENERATE_EC256FP_KEY_PAIR = (byte) 0xAB;    
    final static byte INS_GENERATE_EC256FP_KEY              = (byte) 0xBB;
    final static byte INS_PREPARE_SIGN_WITH_EC256FP         = (byte) 0xAC;
    final static byte INS_SIGN_WITH_EC256FP                 = (byte) 0xBC;
     
    final static short SW_BAD_TEST_DATA_LEN      = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD         = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE   = (short) 0x6711;
    final static short SW_BAD_PIN                = (short) 0x6900;
    
    final static short SW_Exception                      = (short) 0xff01;
    final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    final static short SW_ArithmeticException            = (short) 0xff03;
    final static short SW_ArrayStoreException            = (short) 0xff04;
    final static short SW_NullPointerException           = (short) 0xff05;
    final static short SW_NegativeArraySizeException     = (short) 0xff06;
    final static short SW_CryptoException_prefix         = (short) 0xf100;
    final static short SW_SystemException_prefix         = (short) 0xf200;
    final static short SW_PINException_prefix            = (short) 0xf300;
    final static short SW_TransactionException_prefix    = (short) 0xf400;
    final static short SW_CardRuntimeException_prefix    = (short) 0xf500;
    
    private short m_apduLogOffset = (short) 0;

    final static short RAMDataSize = (short) 0x100;
    final static short RAMKeySize  = (short) 0x100;
    final static short RAMGSize = (short) 0x0080;
    private byte m_RAMData[] = null;
    private byte m_RAMKey[]  = null;
    private byte m_RAMEC[]    = null;
    
    //-------------------------------------------------------------------------//

    private RandomData m_secureRandom  = null;

    private KeyPair m_RSAKeyPair       = null;
    private KeyPair m_EC192FPKeyPair   = null;
    private KeyPair m_EC256FPKeyPair   = null;
    private Key m_RSAPrivateKey        = null;
    private Key m_RSAPublicKey         = null;
    private Key m_ECPrivateKey         = null;
    private Key m_ECPublicKey          = null;
    
    private Signature m_RSASign        = null;
    private Signature m_EC192FPSign    = null;
    private Signature m_EC256FPSign    = null;
    
    private AESKey m_aesKey            = null;
    private DESKey m_desKey            = null;

    private Cipher m_aesCipher         = null;
    private Cipher m_desCipher         = null;

    private MessageDigest m_SHA1Hash   = null;
    private MessageDigest m_SHA256Hash = null;

    //-------------------------------------------------------------------------//
    
    /**
     * AppletTest default constructor
     * Only this class's install method should create the applet object.
     * @param buffer
     * @param offset
     * @param length
     */
    protected PowerAnalysisApplet(byte[] buffer, short offset, byte length)
    {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {
            // Install parameter detail. Compliant with OP 2.0.1.

            // | size | content
            // |------|---------------------------
            // |  1   | [AID_Length]
            // | 5-16 | [AID_Bytes]
            // |  1   | [Privilege_Length]
            // | 1-n  | [Privilege_Bytes] (normally 1Byte)
            // |  1   | [Application_Proprietary_Length]
            // | 0-m  | [Application_Proprietary_Bytes]

            // shift to privilege offset
            dataOffset += (short)(1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)(1 + buffer[dataOffset]);

            // go to proprietary data
            dataOffset++;
            
            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_RAMData = JCSystem.makeTransientByteArray(RAMDataSize, JCSystem.CLEAR_ON_DESELECT);
            m_RAMKey = JCSystem.makeTransientByteArray(RAMKeySize, JCSystem.CLEAR_ON_DESELECT);
            m_RAMEC = JCSystem.makeTransientByteArray(RAMGSize, JCSystem.CLEAR_ON_DESELECT);
            // update flag
            isOP2 = true;
        }
        
        register();
    }
    
    /**
     * Method installing the applet.
     * 
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        new PowerAnalysisApplet(bArray, bOffset, bLength);
    }
        
    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {
        return;
    }

    public void process(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        if (selectingApplet())
            return;
        try {    
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_THIS_APPLET) {
                switch (apduBuffer[ISO7816.OFFSET_INS])
                {
                    case INS_PREPARE_GENERATE_RNGS:
                        this.prepareGenRNGsInSequence(apdu);
                        break;
                    case INS_GENERATE_RNGS:
                        this.genRNGsInSequence(apdu);
                        break;
                    case INS_PREPARE_AES256_SET_KEY:
                        this.prepareAESSetKey(apdu);
                        break;
                    case INS_AES256_SET_KEY:
                        this.AESSetKey(apdu);
                        break;
                    case INS_PREPARE_3DES_SET_KEY:
                        this.prepareDESSetKey(apdu);
                        break;
                    case INS_3DES_SET_KEY:
                        this.DESSetKey(apdu);
                        break;
                    case INS_PREPARE_AES256_ENCRYPT:
                        this.prepareAESEncrypt(apdu);
                        break;
                    case INS_AES256_ENCRYPT:
                        this.AESEncrypt(apdu);
                        break;
                    case INS_PREPARE_3DES_ENCRYPT:
                        this.prepareDESEncrypt(apdu);
                        break;
                    case INS_3DES_ENCRYPT:
                        this.DESencrypt(apdu);
                        break;
                    case INS_PREPARE_SHA1_MESSAGE_DIGEST:
                        this.prepareSHA1Digest(apdu);
                        break;
                    case INS_SHA1_MESSAGE_DIGEST:
                        this.SHA1Digest(apdu);
                        break;
                    case INS_PREPARE_SHA256_MESSAGE_DIGEST:
                        this.prepareSHA256Digest(apdu);
                        break;
                    case INS_SHA256_MESSAGE_DIGEST:
                        this.SHA256Digest(apdu);
                        break;
                    case INS_PREPARE_GENERATE_RSA512_KEY_PAIR:
                        this.prepareGenRSA512KeyPair(apdu);
                        break;
                    case INS_GENERATE_RSA512_KEY:
                        this.genRSA512KeyPair(apdu);
                        break;
                    case INS_PREPARE_SIGN_WITH_RSA512:
                        this.prepareSignRSA512(apdu);
                        break;
                    case INS_SIGN_WITH_RSA512:
                        this.signRSA512(apdu);
                        break;
                    case INS_PREPARE_GENERATE_EC192FP_KEY_PAIR:
                        this.prepareGenEC192FPKeyPair(apdu);
                        break;
                    case INS_GENERATE_EC192FP_KEY:
                        this.genEC192FPKeyPair(apdu);
                        break;
                    case INS_PREPARE_SIGN_WITH_EC192FP:
                        this.prepareSignEC192FP(apdu);
                        break;
                    case INS_SIGN_WITH_EC192FP:
                        this.signEC192FP(apdu);
                        break;
                    case INS_PREPARE_GENERATE_EC256FP_KEY_PAIR:
                        this.prepareGenEC256FPKeyPair(apdu);
                        break;
                    case INS_GENERATE_EC256FP_KEY:
                        this.genEC256FPKeyPair(apdu);
                        break;
                    case INS_PREPARE_SIGN_WITH_EC256FP:
                        this.prepareSignEC256FP(apdu);
                        break;
                    case INS_SIGN_WITH_EC256FP:
                        this.signEC256FP(apdu);
                        break;                                               
                    default:
                        // The INS code is not supported by the dispatcher
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    break;
                }
            }
            else ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        } catch (ISOException e) {
            throw e;
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(SW_Exception);
        }
    }
    
    private void beginDivision() {
        short pauseOuterCycles = 1000;
        for (short i = 0; i < pauseOuterCycles; i++) { }        
        m_secureRandom.generateData(m_RAMData, (short) 0, (short) 128);
    }
    
    private void middleDivision() {
        short pauseInnerCycles = 100;
        m_secureRandom.generateData(m_RAMData, (short) 0, (short) 128);
        for (short i = 0; i < pauseInnerCycles; i++) { }        
        m_secureRandom.generateData(m_RAMData,  (short) 0, (short) 128);
    }
    
    private void endDivision() {
        short pauseOuterCycles = 1000;
        short pauseInnerCycles = 100;
        m_secureRandom.generateData(m_RAMData,  (short) 0, (short) 128);
        for (short i = 0; i < pauseInnerCycles; i++) { }        
        m_secureRandom.generateData(m_RAMData, (short) 0, (short) 128);
        for (short i = 0; i < pauseInnerCycles; i++) { }        
        m_secureRandom.generateData(m_RAMData,  (short) 0, (short) 128);
        for (short i = 0; i < pauseOuterCycles; i++) { }
    }

    private void prepareGenRNGsInSequence(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }   
    private void genRNGsInSequence(APDU apdu) {
        short pauseCycles = 1000;

        for (short i = 0; i < pauseCycles; i++) { }
        m_secureRandom.generateData(m_RAMData, (short) 0, (short) 128);
        for (short i = 0; i < pauseCycles; i++) { }
        m_secureRandom.generateData(m_RAMData, (short) 0, (short) 128);
        m_secureRandom.generateData(m_RAMData, (short) 0, (short) 128);
        for (short i = 0; i < pauseCycles; i++) { }
        m_secureRandom.generateData(m_RAMData, (short) 0, (short) 128);
        m_secureRandom.generateData(m_RAMData, (short) 0, (short) 128);
        m_secureRandom.generateData(m_RAMData, (short) 0, (short) 128);
        for (short i = 0; i < pauseCycles; i++) { }
    }
    
    void prepareAESSetKey(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_aesKey == null)
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        m_secureRandom.generateData(m_RAMKey, (short) 0, (short) 256);
    }
    void AESSetKey(APDU apdu) {
        beginDivision();
        
        m_aesKey.setKey(m_RAMKey, (short) 0);
        
        middleDivision();
        
        m_aesKey.setKey(m_RAMKey, (short) 0);
        
        endDivision();
    }

    void prepareDESSetKey(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_desKey == null)
            m_desKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
        m_secureRandom.generateData(m_RAMKey, (short) 0, (short) 256);
    }
    void DESSetKey(APDU apdu) {
        beginDivision();
        
        m_desKey.setKey(m_RAMKey, (short) 0);
        
        middleDivision();
        
        m_desKey.setKey(m_RAMKey, (short) 0);
        
        endDivision();
    }
    
    void prepareAESEncrypt(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_aesCipher == null) {
            m_aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_aesKey.setKey(m_RAMKey, (short) 0);
            m_aesCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
        }
    }
    void AESEncrypt(APDU apdu) {       
        beginDivision();
        
        m_aesCipher.doFinal(m_RAMData, (short) 0, (short) 16, m_RAMData, (short) 16);
        
        middleDivision();
        
        m_aesCipher.doFinal(m_RAMData, (short) 0, (short) 16, m_RAMData, (short) 16);
        
        endDivision();
    }
    
    void prepareDESEncrypt(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_desCipher == null) {
            m_desCipher = Cipher.getInstance(Cipher.ALG_DES_CBC_NOPAD, false);
            m_desKey.setKey(m_RAMData, (short) 0);
            m_desCipher.init(m_desKey, Cipher.MODE_ENCRYPT);
        }
    }
    void DESencrypt(APDU apdu) {
        beginDivision();
        
        m_desCipher.doFinal(m_RAMData, (short) 0, (short) 16, m_RAMData, (short) 16);
        
        middleDivision();
        
        m_desCipher.doFinal(m_RAMData, (short) 0, (short) 16, m_RAMData, (short) 16);
        
        endDivision();
    }
    
    void prepareSHA1Digest(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_SHA1Hash == null)
            m_SHA1Hash = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
    }
    void SHA1Digest(APDU apdu) {
        beginDivision();
        
        m_SHA1Hash.doFinal(m_RAMData, (short) 0, (short) 16, m_RAMData, (short) 16);
        
        middleDivision();
        
        m_SHA1Hash.doFinal(m_RAMData, (short) 0, (short) 16, m_RAMData, (short) 16);
        
        endDivision();
    }
    
    void prepareSHA256Digest(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_SHA256Hash == null)
            m_SHA256Hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    }
    void SHA256Digest(APDU apdu) {
        beginDivision();
        
        m_SHA256Hash.doFinal(m_RAMData, (short) 0, (short) 16, m_RAMData, (short) 0);
        
        middleDivision();
        
        m_SHA256Hash.doFinal(m_RAMData, (short) 0, (short) 16, m_RAMData, (short) 0);
        
        endDivision();
    }
    
    private void prepareGenRSA512KeyPair(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_RSAKeyPair == null)
            m_RSAKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512);
    }     
    private void genRSA512KeyPair(APDU apdu) {
        for (short i = 0; i < 5000; i++) {}
        m_RSAKeyPair.genKeyPair();
        for (short i = 0; i < 5000; i++) {}        
    }
    
    private void prepareSignRSA512(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_RSAKeyPair == null)
            m_RSAKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512);

        m_RSAKeyPair.genKeyPair();
        m_RSAPublicKey = m_RSAKeyPair.getPublic();
        m_RSAPrivateKey = m_RSAKeyPair.getPrivate();

        if (m_RSASign == null) {
            m_RSASign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            m_RSASign.init(m_RSAPrivateKey, Signature.MODE_SIGN);
        }
    }
    private void signRSA512(APDU apdu) {
        beginDivision();
        
        m_RSASign.sign(m_RAMData, (short) 0, (short) 16, m_RAMData, (short) 16);

        middleDivision();
        
        m_RSASign.sign(m_RAMData, (short) 0, (short) 16, m_RAMData, (short) 16);

        endDivision();
    }
    
    public void allocatePair(byte keyClass, short keyLength) {
        if (keyLength == 192){
            m_EC192FPKeyPair = new KeyPair(keyClass, keyLength);
            if (m_EC192FPKeyPair.getPublic() == null || m_EC192FPKeyPair.getPrivate() == null) {
                try {
                    m_EC192FPKeyPair.genKeyPair();
                } catch (Exception ignored) {
                }
            }
        } else {
            m_EC256FPKeyPair = new KeyPair(keyClass, keyLength);
            if (m_EC256FPKeyPair.getPublic() == null || m_EC256FPKeyPair.getPrivate() == null) {
                try {
                    m_EC256FPKeyPair.genKeyPair();
                } catch (Exception ignored) {
                }
            }
        }
    }
    public void setCurve(KeyPair keypair, byte key, byte curve, short params, byte[] buffer, short offset) {
        byte alg = ECConsts.getCurveType(curve);

        if (params == ECConsts.PARAMETERS_NONE) {
            return;
        }

        short length;
        if (alg == KeyPair.ALG_EC_FP && (params & ECConsts.PARAMETER_FP) != 0) {
            length = ECConsts.getCurveParameter(curve, ECConsts.PARAMETER_FP, buffer, offset);
            setParameter(keypair, key, ECConsts.PARAMETER_FP, buffer, offset, length);
        }

        short paramMask = ECConsts.PARAMETER_A;
        while (paramMask <= ECConsts.PARAMETER_S) {
            short masked = (short) (paramMask & params);
            if (masked != 0) {
                length = ECConsts.getCurveParameter(curve, masked, buffer, offset);
                setParameter(keypair, key, masked, buffer, offset, length);
            }
            paramMask = (short) (paramMask << 1);
        }
    }
    public void setParameter(KeyPair keypair, byte key, short param, byte[] data, short offset, short length) {
        ECPublicKey ecPublicKey = null;
        ECPrivateKey ecPrivateKey = null;
        ecPublicKey = (ECPublicKey) keypair.getPublic();
        ecPrivateKey = (ECPrivateKey) keypair.getPrivate();

        switch (param) {
            case ECConsts.PARAMETER_FP:
                if ((key & ECConsts.KEY_PUBLIC) != 0) ecPublicKey.setFieldFP(data, offset, length);
                if ((key & ECConsts.KEY_PRIVATE) != 0) ecPrivateKey.setFieldFP(data, offset, length);
                break;
            case ECConsts.PARAMETER_A:
                if ((key & ECConsts.KEY_PUBLIC) != 0) ecPublicKey.setA(data, offset, length);
                if ((key & ECConsts.KEY_PRIVATE) != 0) ecPrivateKey.setA(data, offset, length);
                break;
            case ECConsts.PARAMETER_B:
                    if ((key & ECConsts.KEY_PUBLIC) != 0) ecPublicKey.setB(data, offset, length);
                    if ((key & ECConsts.KEY_PRIVATE) != 0) ecPrivateKey.setB(data, offset, length);
                break;
            case ECConsts.PARAMETER_G:
                    if ((key & ECConsts.KEY_PUBLIC) != 0) ecPublicKey.setG(data, offset, length);
                    if ((key & ECConsts.KEY_PRIVATE) != 0) ecPrivateKey.setG(data, offset, length);
                break;
            case ECConsts.PARAMETER_R:
                    if ((key & ECConsts.KEY_PUBLIC) != 0) ecPublicKey.setR(data, offset, length);
                    if ((key & ECConsts.KEY_PRIVATE) != 0) ecPrivateKey.setR(data, offset, length);
                break;
            case ECConsts.PARAMETER_K:
                short k = 0;
                if (length > 2 || length <= 0) {
                    break;
                } else if (length == 2) {
                    k = Util.getShort(data, offset);
                } else if (length == 1) {
                    k = data[offset];
                }
                    if ((key & ECConsts.KEY_PUBLIC) != 0) ecPublicKey.setK(k);
                    if ((key & ECConsts.KEY_PRIVATE) != 0) ecPrivateKey.setK(k);
                break;
            case ECConsts.PARAMETER_S:
                if ((key & ECConsts.KEY_PRIVATE) != 0) ecPrivateKey.setS(data, offset, length);
                break;
            case ECConsts.PARAMETER_W:
                if ((key & ECConsts.KEY_PUBLIC) != 0) ecPublicKey.setW(data, offset, length);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
    }
    void prepareGenEC192FPKeyPair(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_EC192FPKeyPair == null) {
            allocatePair(KeyPair.ALG_EC_FP, (short) 192);
            setCurve(m_EC192FPKeyPair, ECConsts.KEY_BOTH, ECConsts.CURVE_secp192r1, ECConsts.PARAMETERS_ALL, m_RAMEC, (short) 0);
        }
    }
    void genEC192FPKeyPair(APDU apdu) {
        for (short i = 0; i < 5000; i++) {}
        m_EC192FPKeyPair.genKeyPair();
        for (short i = 0; i < 5000; i++) {} 
    }
    
    private void prepareSignEC192FP(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_EC192FPKeyPair == null) {
            m_EC192FPKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
        }
        
        m_EC192FPKeyPair.genKeyPair();
        m_ECPublicKey = (ECPublicKey) m_EC192FPKeyPair.getPublic();
        m_ECPrivateKey = (ECPrivateKey) m_EC192FPKeyPair.getPrivate();
        
        if (m_EC192FPSign == null) {
            m_EC192FPSign = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
            m_EC192FPSign.init(m_ECPrivateKey, Signature.MODE_SIGN);
        }
    }
    private void signEC192FP(APDU apdu) {
        beginDivision();
        
        m_EC192FPSign.sign(m_RAMData, (short) 0, (short) 16, m_RAMData, (byte) 16);

        middleDivision();
        
        m_EC192FPSign.sign(m_RAMData, (short) 0, (short) 16, m_RAMData, (byte) 16);
        
        endDivision();
    }
    
    void prepareGenEC256FPKeyPair(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_EC256FPKeyPair == null) {
            allocatePair(KeyPair.ALG_EC_FP, (short) 256);
            setCurve(m_EC256FPKeyPair, ECConsts.KEY_BOTH, ECConsts.CURVE_secp256r1, ECConsts.PARAMETERS_ALL, m_RAMEC, (short) 0);
        }
    }
    void genEC256FPKeyPair(APDU apdu) {
        for (short i = 0; i < 5000; i++) {}
        m_EC256FPKeyPair.genKeyPair();
        for (short i = 0; i < 5000; i++) {} 
    }
    
    private void prepareSignEC256FP(APDU apdu) {
        if (m_secureRandom == null)
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        if (m_EC256FPKeyPair == null) {
            allocatePair(KeyPair.ALG_EC_FP, (short) 256);
            setCurve(m_EC256FPKeyPair, ECConsts.KEY_BOTH, ECConsts.CURVE_secp256r1, ECConsts.PARAMETERS_ALL, m_RAMEC, (short) 0);
        }
        
        m_EC256FPKeyPair.genKeyPair();
        m_ECPublicKey = (ECPublicKey) m_EC256FPKeyPair.getPublic();
        m_ECPrivateKey = (ECPrivateKey) m_EC256FPKeyPair.getPrivate();
        
        if (m_EC256FPSign == null) {
            m_EC256FPSign = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
            m_EC256FPSign.init(m_ECPrivateKey, Signature.MODE_SIGN);
        }
    }
    private void signEC256FP(APDU apdu) {
        beginDivision();
        
        m_EC256FPSign.sign(m_RAMData, (short) 0, (short) 16, m_RAMData, (byte) 0);

        middleDivision();
        
        m_EC256FPSign.sign(m_RAMData, (short) 0, (short) 16, m_RAMData, (byte) 0);
        
        endDivision();
    }
}

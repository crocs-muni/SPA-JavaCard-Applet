package simpleapdu;

import power_analysis_applets.SimpleApplet;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import javacard.framework.Util;
import javax.smartcardio.ResponseAPDU;
import power_analysis_applets.PowerAnalysisApplet;

/**
 *
 * @author xsvenda
 */
public class SimpleAPDU {
    static CardMngr cardManager = new CardMngr();

    private static byte DEFAULT_USER_PIN[] = {(byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30};
    private static byte NEW_USER_PIN[] = {(byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31};
    private static byte APPLET_AID[] = {(byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70, (byte) 0x6C, 
        (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    private static byte SELECT_SIMPLEAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, 
        (byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70, (byte) 0x6C,
        (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};

    private static final byte RNG_DATA[] = { (byte) 0xB0, (byte) 0x54, (byte) 0x10, (byte) 0x00, (byte) 0x00};
    
    private static byte[] getResponseData(byte[] response) {
        byte[] responseData = new byte[response.length - 2];
        Util.arrayCopyNonAtomic(response, (short) 0, responseData, (short) 0, (short) (response.length - 2));
        return responseData;
    }
    
    private static byte[] getResponseCode(byte[] response) {
        byte[] responseCode = new byte[2];
        Util.arrayCopyNonAtomic(response, (short) (response.length - 2), responseCode, (short) 0, (short) 2);
        return responseCode;
    }
    
    private static void parseResponse(byte[] response) {
        System.out.println("-- -- -- -- --");
        byte[] responseData = getResponseData(response);
        System.out.println(responseData.length);
        if (responseData.length == 0) {
            System.out.println("No response data");
        } else {
            System.out.println(CardMngr.bytesToHex(responseData));
        }
        byte[] responseCode = getResponseCode(response);
        System.out.println(CardMngr.bytesToHex(responseCode));
        System.out.println("-- -- -- -- --");        
    }
       
    private static short getShortFromByteHex(byte[] bytes) {
        String str = CardMngr.byteToHex(bytes[1]);
        char fst = str.charAt(0);
        char snd = str.charAt(1);
        short fstNum = 0;
        short sndNum = 0;
        switch (fst) {
            case '1': fstNum = 1; break;
            case '2' : fstNum = 2; break;
            case '3' : fstNum = 3; break;
            case '4' : fstNum = 4; break;
            case '5' : fstNum = 5; break;
            case '6' : fstNum = 6; break;
            case '7' : fstNum = 7; break;
            case '8' : fstNum = 8; break;
            case '9' : fstNum = 9; break;
            case 'a' : fstNum = 10; break;
            case 'b' : fstNum = 11; break;
            case 'c' : fstNum = 12; break;
            case 'd' : fstNum = 13; break;
            case 'e' : fstNum = 14; break;
            case 'f' : fstNum = 15; break;
        }
        switch (snd) {
            case '1': sndNum = 1; break;
            case '2' : sndNum = 2; break;
            case '3' : sndNum = 3; break;
            case '4' : sndNum = 4; break;
            case '5' : sndNum = 5; break;
            case '6' : sndNum = 6; break;
            case '7' : sndNum = 7; break;
            case '8' : sndNum = 8; break;
            case '9' : sndNum = 9; break;
            case 'a' : sndNum = 10; break;
            case 'b' : sndNum = 11; break;
            case 'c' : sndNum = 12; break;
            case 'd' : sndNum = 13; break;
            case 'e' : sndNum = 14; break;
            case 'f' : sndNum = 15; break;
        }
        return (short) (16*fstNum + sndNum);
    }
    
    private static byte[] task1(short additionalDataLen) throws Exception {
        byte apduT1[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        apduT1[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apduT1[CardMngr.OFFSET_INS] = (byte) 0x54;
        apduT1[CardMngr.OFFSET_P1] = (byte) 0x10;
        apduT1[CardMngr.OFFSET_P2] = (byte) 0x00;
        apduT1[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
        byte[] response = cardManager.sendAPDUSimulator(apduT1);
        parseResponse(response);
        return getResponseData(response);
    }
    
    private static byte[] task2(short additionalDataLen, byte[] installData) throws Exception {
        additionalDataLen = 0x10;
        byte apduT2[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        apduT2[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apduT2[CardMngr.OFFSET_INS] = (byte) 0x50;
        apduT2[CardMngr.OFFSET_P1] = (byte) 0x00;
        apduT2[CardMngr.OFFSET_P2] = (byte) 0x00;
        apduT2[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
        if (additionalDataLen != 0) {
            Util.arrayCopyNonAtomic(installData, (short) 0, apduT2, CardMngr.OFFSET_DATA, additionalDataLen);
        }
        byte[] response = cardManager.sendAPDUSimulator(apduT2);
        parseResponse(response);
        return getResponseData(response);
    }
    
    private static void task3(short additionalDataLen, byte[] installData) throws Exception {
        additionalDataLen = 0x10;
        byte apduT3[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        apduT3[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apduT3[CardMngr.OFFSET_INS] = (byte) 0x51;
        apduT3[CardMngr.OFFSET_P1] = (byte) 0x00;
        apduT3[CardMngr.OFFSET_P2] = (byte) 0x00;
        apduT3[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
        if (additionalDataLen != 0) {
            Util.arrayCopyNonAtomic(installData, (short) 0, apduT3, CardMngr.OFFSET_DATA, additionalDataLen);
        }
        byte[] response = cardManager.sendAPDUSimulator(apduT3);
        parseResponse(response);
    }
    
    private static void task4(short additionalDataLen, byte[] installData) throws Exception {
        additionalDataLen = 0x10;
        byte apduT2[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        apduT2[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apduT2[CardMngr.OFFSET_INS] = (byte) 0x58;
        apduT2[CardMngr.OFFSET_P1] = (byte) 0x01;
        apduT2[CardMngr.OFFSET_P2] = (byte) 0x00;
        apduT2[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
        if (additionalDataLen != 0) {
            Util.arrayCopyNonAtomic(installData, (short) 0, apduT2, CardMngr.OFFSET_DATA, additionalDataLen);
        }
        byte[] response = cardManager.sendAPDUSimulator(apduT2);
        parseResponse(response);
        
        short toSend = getShortFromByteHex(getResponseCode(response));
        additionalDataLen = 0x00;

        apduT2[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apduT2[CardMngr.OFFSET_INS] = (byte) 0x58;
        apduT2[CardMngr.OFFSET_P1] = (byte) 0x02;
        apduT2[CardMngr.OFFSET_P2] = (byte) toSend;
        apduT2[CardMngr.OFFSET_LC] = (byte) 0x00;
        if (additionalDataLen != 0) {
            Util.arrayCopyNonAtomic(installData, (short) 0, apduT2, CardMngr.OFFSET_DATA, additionalDataLen);
        }
        response = cardManager.sendAPDUSimulator(apduT2);
        parseResponse(response);
    }
    
    public static void main(String[] args) {
        try {
            //
            // SIMULATED CARDS
            //
            
            // Prepare simulated card 
            byte[] installData = new byte[10]; // no special install data passed now - can be used to pass initial keys etc.
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, PowerAnalysisApplet.class);      
            
            // TODO: prepare proper APDU command
            short additionalDataLen = 0x10;
            byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            apdu[CardMngr.OFFSET_CLA] = (byte) 0x00;
            apdu[CardMngr.OFFSET_INS] = (byte) 0x00;
            apdu[CardMngr.OFFSET_P1] = (byte) 0x00;
            apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
            apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
            
            // TODO: if additional data are supplied (additionalDataLen != 0), then copy input data here starting from CardMngr.OFFSET_DATA
            if (additionalDataLen != 0) {
                Util.arrayCopyNonAtomic(installData, (short) 0, apdu, CardMngr.OFFSET_DATA, additionalDataLen);
            }
            
            // NOTE: we are using sendAPDUSimulator() instead of sendAPDU()
            byte[] response = cardManager.sendAPDUSimulator(apdu); 
            
            // TODO: parse response[] data - data + 2B response code
            parseResponse(response);
            
            // TODO Task1: Create proper command to generate random data on (simulated) card
            byte[] randomData = task1(additionalDataLen); // tesk1 returns byte field with length 16!!!
 
            // TODO Task2: Create proper command to encrypt data on (simulated) card
            byte[] encryptedRandomData = task2(additionalDataLen, randomData);

            // TODO Task3: Create proper command to decrypt data on (simulated) card
            task3(additionalDataLen, encryptedRandomData);
            
            // TODO Task4: Sign data with RSA algorithm
            task4(additionalDataLen, randomData);
            
            //
            // REAL CARDS
            //
/*            
            // TODO: Try same with real card
            if (cardManager.ConnectToCard()) {
                // Select our application on card
                cardManager.sendAPDU(SELECT_SIMPLEAPPLET);
                
                // TODO: send proper APDU
                ResponseAPDU output = cardManager.sendAPDU(RNG_DATA);
                
                cardManager.DisconnectFromCard();
            } else {
                System.out.println("Failed to connect to card");
            }
            
/**/
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
}

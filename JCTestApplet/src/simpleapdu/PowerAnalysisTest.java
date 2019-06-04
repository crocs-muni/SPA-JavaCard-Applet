/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package simpleapdu;

import javacard.framework.Util;
import power_analysis_applets.PowerAnalysisApplet;

/**
 *
 * @author Martin
 */
public class PowerAnalysisTest {
    static CardMngr cardManager = new CardMngr();
    
    private static final byte APPLET_AID[] = {(byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70, (byte) 0x6C, 
        (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    private static final byte[] INSTRUCTIONS = new byte[]
    {
        PowerAnalysisAppletInstructions.INS_PREPARE_GENERATE_RNGS,
        PowerAnalysisAppletInstructions.INS_GENERATE_RNGS,
        PowerAnalysisAppletInstructions.INS_PREPARE_AES256_SET_KEY,
        PowerAnalysisAppletInstructions.INS_AES256_SET_KEY,
        PowerAnalysisAppletInstructions.INS_PREPARE_3DES_SET_KEY,
        PowerAnalysisAppletInstructions.INS_3DES_SET_KEY,
        PowerAnalysisAppletInstructions.INS_PREPARE_AES256_ENCRYPT,
        PowerAnalysisAppletInstructions.INS_AES256_ENCRYPT,
        PowerAnalysisAppletInstructions.INS_PREPARE_3DES_ENCRYPT, 
        PowerAnalysisAppletInstructions.INS_3DES_ENCRYPT,     
        PowerAnalysisAppletInstructions.INS_PREPARE_SHA1_MESSAGE_DIGEST, 
        PowerAnalysisAppletInstructions.INS_SHA1_MESSAGE_DIGEST, 
        PowerAnalysisAppletInstructions.INS_PREPARE_SHA256_MESSAGE_DIGEST,
        PowerAnalysisAppletInstructions.INS_SHA256_MESSAGE_DIGEST,
        PowerAnalysisAppletInstructions.INS_PREPARE_GENERATE_RSA512_KEY_PAIR,  
        PowerAnalysisAppletInstructions.INS_GENERATE_RSA512_KEY, 
        PowerAnalysisAppletInstructions.INS_PREPARE_SIGN_WITH_RSA512,  
        PowerAnalysisAppletInstructions.INS_SIGN_WITH_RSA512,  
        PowerAnalysisAppletInstructions.INS_PREPARE_GENERATE_EC192FP_KEY_PAIR,     
        PowerAnalysisAppletInstructions.INS_GENERATE_EC192FP_KEY,
        PowerAnalysisAppletInstructions.INS_PREPARE_SIGN_WITH_EC192FP,
        PowerAnalysisAppletInstructions.INS_SIGN_WITH_EC192FP,
        PowerAnalysisAppletInstructions.INS_PREPARE_GENERATE_EC256FP_KEY_PAIR,     
        PowerAnalysisAppletInstructions.INS_GENERATE_EC256FP_KEY,
        PowerAnalysisAppletInstructions.INS_PREPARE_SIGN_WITH_EC256FP,
        PowerAnalysisAppletInstructions.INS_SIGN_WITH_EC256FP
    };
    
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
    
    private static byte[] APDU(byte instruction) throws Exception {
        short additionalDataLen = (short) 0;
        byte apdu00[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        apdu00[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apdu00[CardMngr.OFFSET_INS] = instruction;
        apdu00[CardMngr.OFFSET_P1] = (byte) 0x00;
        apdu00[CardMngr.OFFSET_P2] = (byte) 0x00;
        apdu00[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
        byte[] response = cardManager.sendAPDUSimulator(apdu00);
        return getResponseData(response);
    }
    
    private static void runTests(byte[] instructions) throws Exception {
        for (int i = 0; i < instructions.length; i++) {
            APDU(instructions[i]);
        }
    }
    
    public static void main(String[] args) {
        try {
            byte[] installData = new byte[10]; // no special install data passed now - can be used to pass initial keys etc.
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, PowerAnalysisApplet.class);      
            
            runTests(INSTRUCTIONS);
            
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
}

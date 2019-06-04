/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package simpleapdu;

/**
 *
 * @author Martin
 */
public class PowerAnalysisAppletInstructions {
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
}

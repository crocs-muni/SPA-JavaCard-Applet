package simpleapdu;

import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import java.util.List;
import javacard.framework.AID;
import javax.smartcardio.*;

/**
 *
 * @author xsvenda
 */
public class CardMngr {
    CardTerminal m_terminal = null;
    CardChannel m_channel = null;
    Card m_card = null;
    
    // Simulator related attributes
    private static CAD m_cad = null;
    private static JavaxSmartCardInterface m_simulator = null;

    
    private final byte selectCM[] = {
        (byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x07, (byte) 0xa0, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x18, (byte) 0x43, (byte) 0x4d};

    public static final byte OFFSET_CLA = 0x00;
    public static final byte OFFSET_INS = 0x01;
    public static final byte OFFSET_P1 = 0x02;
    public static final byte OFFSET_P2 = 0x03;
    public static final byte OFFSET_LC = 0x04;
    public static final byte OFFSET_DATA = 0x05;
    public static final byte HEADER_LENGTH = 0x05;
    public final static short DATA_RECORD_LENGTH = (short) 0x80; // 128B per record
    public final static short NUMBER_OF_RECORDS = (short) 0x0a; // 10 records

    public boolean ConnectToCard() throws Exception {
        // TRY ALL READERS, FIND FIRST SELECTABLE
        List terminalList = GetReaderList();

        if (terminalList.isEmpty()) {
            System.out.println("No terminals found");
        }

        //List numbers of Card readers
        boolean cardFound = false;
        for (int i = 0; i < terminalList.size(); i++) {
            System.out.println(i + " : " + terminalList.get(i));
            m_terminal = (CardTerminal) terminalList.get(i);
            if (m_terminal.isCardPresent()) {
                m_card = m_terminal.connect("*");
                System.out.println("card: " + m_card);
                m_channel = m_card.getBasicChannel();

                //reset the card
                ATR atr = m_card.getATR();
                System.out.println(bytesToHex(m_card.getATR().getBytes()));
                
                cardFound = true;
            }
        }

        return cardFound;
    }

    public void DisconnectFromCard() throws Exception {
        if (m_card != null) {
            m_card.disconnect(false);
            m_card = null;
        }
    }

    public byte[] GetCPLCData() throws Exception {
        byte[] data;

        // TODO: Modify to obtain CPLC data
        byte apdu[] = new byte[HEADER_LENGTH];
        apdu[OFFSET_CLA] = (byte) 0x00;
        apdu[OFFSET_INS] = (byte) 0x00;
        apdu[OFFSET_P1] = (byte) 0x00;
        apdu[OFFSET_P2] = (byte) 0x00;
        apdu[OFFSET_LC] = (byte) 0x00;

        ResponseAPDU resp = sendAPDU(apdu);
        if (resp.getSW() != 0x9000) { // 0x9000 is "OK"
            System.out.println("Fail to obtain card's response data");
            data = null;
        } else {
            byte temp[] = resp.getBytes();
            data = new byte[temp.length - 2];
            System.arraycopy(temp, 0, data, 0, temp.length - 2);
            // Last two bytes are status word (also obtainable by resp.getSW())
            // Take a look at ISO7816_status_words.txt for common codes
        }

        return data;
    }

    public void ProbeCardCommands() throws Exception {
        // TODO: modify to probe for instruction
        for (int i = 0; i <= 0; i++) {
            byte apdu[] = new byte[HEADER_LENGTH];
            apdu[OFFSET_CLA] = (byte) 0x00;
            apdu[OFFSET_INS] = (byte) 0x00;
            apdu[OFFSET_P1] = (byte) 0x00;
            apdu[OFFSET_P2] = (byte) 0x00;
            apdu[OFFSET_LC] = (byte) 0x00;

            ResponseAPDU resp = sendAPDU(apdu);
            
            System.out.println("Response: " + Integer.toHexString(resp.getSW()));  
            
            if (resp.getSW() != 0x6D00) { // Note: 0x6D00 is SW_INS_NOT_SUPPORTED
                // something?
            }
        }
    }
    
    public List GetReaderList() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List readersList = factory.terminals().list();
            return readersList;
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
            return null;
        }
    }

    public ResponseAPDU sendAPDU(byte apdu[]) throws Exception {
        CommandAPDU commandAPDU = new CommandAPDU(apdu);

        System.out.println(">>>>");
        System.out.println(commandAPDU);

        System.out.println(bytesToHex(commandAPDU.getBytes()));

        ResponseAPDU responseAPDU = m_channel.transmit(commandAPDU);

        System.out.println(responseAPDU);
        System.out.println(bytesToHex(responseAPDU.getBytes()));

        if (responseAPDU.getSW1() == (byte) 0x61) {
            CommandAPDU apduToSend = new CommandAPDU((byte) 0x00,
                    (byte) 0xC0, (byte) 0x00, (byte) 0x00,
                    (int) responseAPDU.getSW1());

            responseAPDU = m_channel.transmit(apduToSend);
            System.out.println(bytesToHex(responseAPDU.getBytes()));
        }

        System.out.println("<<<<");

        return (responseAPDU);
    }

    public static String byteToHex(byte data) {
        StringBuilder buf = new StringBuilder();
        buf.append(toHexChar((data >>> 4) & 0x0F));
        buf.append(toHexChar(data & 0x0F));
        return buf.toString();
    }

    public static char toHexChar(int i) {
        if ((0 <= i) && (i <= 9)) {
            return (char) ('0' + i);
        } else {
            return (char) ('a' + (i - 10));
        }
    }

    public static String bytesToHex(byte[] data) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            buf.append(byteToHex(data[i]));
            buf.append(" ");
        }
        return (buf.toString());
    }
    
    
    public boolean prepareLocalSimulatorApplet(byte[] appletAIDArray, byte[] installData, Class appletClass) {
        System.setProperty("com.licel.jcardsim.terminal.type", "2");
        m_cad = new CAD(System.getProperties());
        m_simulator = (JavaxSmartCardInterface) m_cad.getCardInterface();
        AID appletAID = new AID(appletAIDArray, (short) 0, (byte) appletAIDArray.length);

        AID appletAIDRes =  m_simulator.installApplet(appletAID, appletClass, installData, (short) 0, (byte) installData.length);
        return m_simulator.selectApplet(appletAID);
    }
    
    public byte[] sendAPDUSimulator(byte apdu[]) throws Exception {
        System.out.println(">>>>");
        System.out.println(bytesToHex(apdu));

        byte[] responseBytes = m_simulator.transmitCommand(apdu);

        System.out.println(bytesToHex(responseBytes));
        System.out.println("<<<<");

        return responseBytes;
    }
    
    
}

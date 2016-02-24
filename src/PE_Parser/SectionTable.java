/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package PE_Parser;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author zahra
 */
public class SectionTable {

    public long NumberOfSection;
    //public String RVA="";
    //public String Offset="";

    public String Reverse(String S) {
        String R = "";
        for (int i = 0; i < (S.length()) / 2; i++) {
            R += S.substring(S.length() - 2 * (i + 1), S.length() - 2 * (i));
        }
        return R;
    }
    public LinkedList<String> RVA = new LinkedList<String>();
    public LinkedList<String> Offset = new LinkedList<String>();

    public int FindAddress(String Addr) {

        int sectionnumber = 0;
                
        for (int i = 0; i < RVA.size()-1; i++) {
            int res = Addr.compareTo(RVA.get(i));
            if (res > 0) {
                sectionnumber = i;
            }
        }
        return sectionnumber;
    }

    public void show(String FileName, long NumberOfSection, long StartAddr) throws FileNotFoundException, IOException, Exception {
        System.out.println("****SECTION TABLE CONTENT*****");
        RandomAccessFile access = new RandomAccessFile(FileName, "rw");
        access.seek(StartAddr);
        RVA.clear();
        Offset.clear();
        byte[] DHA = new byte[40];
        access.read(DHA);
        for (int i = 0; i < NumberOfSection; i++) {
            System.out.println("Section " + (i + 1));
            int cur = 0;
            STPrintDDw("Name", cur, DHA);
            cur += 8;
            STPrintDw("phisical Address/Virtual Size", cur, DHA);
            cur += 4;
            String R1 = "";
            R1 = STPrintDw("VirtualAddress", cur, DHA);
            cur += 4;
            RVA.addLast(R1);
            STPrintDw("SizeOfRowData", cur, DHA);
            cur += 4;
            R1 = STPrintDw("PointerToRowData", cur, DHA);
            cur += 4;
            Offset.addLast(R1);
            STPrintDw("PointerToRelocations", cur, DHA);
            cur += 4;
            STPrintDw("PointerToLineNumber", cur, DHA);
            cur += 4;
            STPrintw("NumberOfRelocations", cur, DHA);
            cur += 2;
            STPrintw("NumberOfLineNumber", cur, DHA);
            cur += 2;
            STPrintDw("Characteristics", cur, DHA);
            cur += 4;

            StartAddr += cur;
            access.seek(StartAddr);
            access.read(DHA);
        }
    }

    private String byteArrayToHexString(byte[] b) throws Exception {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result +=
                    Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    private String STPrintDw(String Name, int cur, byte[] DHA) throws Exception {
        byte[] Dword = new byte[4];
        System.arraycopy(DHA, cur, Dword, 0, 4);
        String Sword = byteArrayToHexString(Dword);
        System.out.print(Name + ":");
        System.out.println(Reverse(Sword));
        return Reverse(Sword);
    }

    private void STPrintDDw(String Name, int cur, byte[] DHA) throws Exception {
        byte[] Dword = new byte[8];
        System.arraycopy(DHA, cur, Dword, 0, 8);
        String Sword = byteArrayToHexString(Dword);
        System.out.print(Name + ":");
        System.out.println(Reverse(Sword));
    }

    private void STPrintw(String Name, int cur, byte[] DHA) throws Exception {
        byte[] Dword = new byte[2];
        System.arraycopy(DHA, cur, Dword, 0, 2);
        String Sword = byteArrayToHexString(Dword);
        System.out.print(Name + ":");
        System.out.println(Reverse(Sword));
    }
}

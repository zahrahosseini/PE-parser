/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package PE_Parser;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;

/**
 *
 * @author zahra
 */
public class ExportTable {
public String AOF="";// Address of name;

public int sse=0;//number of function;
    public void Show(String FileName, Long StartAdd) throws FileNotFoundException, IOException, Exception {
        System.out.println("^^^^EXPORT TABLE CONTENT^^^^^");
        RandomAccessFile access = new RandomAccessFile(FileName, "rw");
        access.seek(StartAdd);
        byte[] DHA = new byte[40];
        access.read(DHA);
        int cur = 0;
        ETPrintDw("characteristics", cur, DHA);
        cur += 4;
        ETPrintDw("timeDateStamp", cur, DHA);
        cur += 4;
        ETPrintw("Major Version", cur, DHA);
        cur += 2;
        ETPrintw("Minor Version", cur, DHA);
        cur += 2;
        ETPrintDw("nName", cur, DHA);
        cur += 4;
        ETPrintDw("Nbase", cur, DHA);
        cur += 4;
        String Nfunction = ETPrintDw("Number Of Functions", cur, DHA);
        cur += 4;
        ETPrintDw("Number Of Name", cur, DHA);
        cur += 4;
        ETPrintDw("Address Of Functions", cur, DHA);
        cur += 4;
        BigInteger se = new BigInteger(Nfunction, 16);
         sse = se.intValue();
         AOF = ETPrintDw("Address Of Names", cur, DHA);
        cur += 4;

        ETPrintDw("Address Of Name Ordinals", cur, DHA);
        cur += 4;
        System.out.println("==============");

    }

    public BigInteger findoffset(String Addr) {
        SectionTable s = new SectionTable();
        int SecNo = s.FindAddress(Addr);
        BigInteger bi = new BigInteger(Addr, 16);
        BigInteger rva = new BigInteger(s.RVA.get(SecNo), 16);
        BigInteger offset = new BigInteger(s.Offset.get(SecNo), 16);
        BigInteger t = bi.subtract(rva);
        t = t.add(offset);
        return t;
    }

    public String Reverse(String S) {
        String R = "";
        for (int i = 0; i < (S.length()) / 2; i++) {
            R += S.substring(S.length() - 2 * (i + 1), S.length() - 2 * (i));
        }
        return R;
    }

    private String ETPrintDw(String Name, int cur, byte[] DHA) throws Exception {
        byte[] Dword = new byte[4];
        System.arraycopy(DHA, cur, Dword, 0, 4);
        String Sword = byteArrayToHexString(Dword);
        System.out.print(Name + ":");
        System.out.println(Reverse(Sword));

        return (Reverse(Sword));
    }

    private void ETPrintw(String Name, int cur, byte[] DHA) throws Exception {
        byte[] Dword = new byte[2];
        System.arraycopy(DHA, cur, Dword, 0, 2);
        String Sword = byteArrayToHexString(Dword);
        System.out.print(Name + ":");
        System.out.println(Reverse(Sword));
    }

    private String byteArrayToHexString(byte[] b) throws Exception {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result +=
                    Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }
}

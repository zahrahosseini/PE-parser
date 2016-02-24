/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package PE_Parser;

/**
 *
 * @author zahra
 */
import java.io.*;
import java.math.BigInteger;

public class Header {

    private String FileName;

    private String byteArrayToHexString(byte[] b) throws Exception {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result +=
                    Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    public void SetFile(String mFileName) {
        FileName = mFileName;
    }

    public String Reverse(String S) {
        String R = "";
        for (int i = 0; i < (S.length()) / 2; i++) {
            R += S.substring(S.length() - 2 * (i + 1), S.length() - 2 * (i));
        }
        return R;
    }

    public void Show() throws FileNotFoundException, IOException, Exception {
        String S = DosHeader(FileName);
        System.out.println("PE Start At " + S);
        long L = PE(FileName, S);
        L = FileHeader(FileName, L);
        L = OptionalHeader(FileName, L);
        long FS = DataDirectory(FileName, L);
        long NNOS = 0;//int number of section;
        NNOS = Integer.decode("0x" + NOS);
        SectionTable s = new SectionTable();
        BigInteger se = new BigInteger(S, 16);
        String M = "000000f8";
        BigInteger Mm = new BigInteger(M, 16);
        se = se.add(Mm);
        s.show(FileName, NNOS, se.longValue());
        if (SizeExport.compareTo("00000000") > 0) {
            int SecNo = s.FindAddress(SExport);
            BigInteger bi = new BigInteger(SExport, 16);
            BigInteger rva = new BigInteger(s.RVA.get(SecNo), 16);
            BigInteger offset = new BigInteger(s.Offset.get(SecNo), 16);
            BigInteger t = bi.subtract(rva);
            t = t.add(offset);
            ExportTable e = new ExportTable();
            e.Show(FileName, t.longValue());
////////////////////////////////////////////////////////
            if (e.sse > 0) { //number of function above 0
                System.out.println("===Name of Function ===");
                SecNo = s.FindAddress(e.AOF);
                bi = new BigInteger(e.AOF, 16);
                rva = new BigInteger(s.RVA.get(SecNo), 16);
                offset = new BigInteger(s.Offset.get(SecNo), 16);
                t = bi.subtract(rva);
                t = t.add(offset);
                RandomAccessFile access = new RandomAccessFile(FileName, "rw");
                long q = -4;
                for (int j = 0; j < e.sse; j++) {
                    W12(t, s, q);
                    q += 4;
                }

            }
        }
    }

    public void W12(BigInteger t, SectionTable s, long iindex) throws FileNotFoundException, IOException, Exception {
        RandomAccessFile access = new RandomAccessFile(FileName, "rw");

        iindex += 4;
        long tempt = t.longValue();
        access.seek(tempt + iindex);
        byte[] DHA = new byte[4];
        access.read(DHA);
        int cur = 0;
        String NOTU = DosHeaderPrintDw("NOTU", cur, DHA);
        cur += 4;

        int SecNo = s.FindAddress(NOTU);
        BigInteger bi = new BigInteger(NOTU, 16);
        BigInteger rva = new BigInteger(s.RVA.get(SecNo), 16);
        BigInteger offset = new BigInteger(s.Offset.get(SecNo), 16);
        t = bi.subtract(rva);
        BigInteger t1 = t.add(offset);
        Long TT = t1.longValue();
        char c = 'A';
        int index = 0;
        while (c != 0) {
            access.seek(TT + index);
            byte[] DHA1 = new byte[1];
            access.read(DHA1);
            cur = 0;
            String FS12 = NRDosHeaderPrintD1("NOTU11", cur, DHA1);

            int iFS12 = Integer.parseInt(FS12, 16);
            c = (char) iFS12;
            System.out.print(c);
            index++;
        }
        System.out.println();
    }
    String SExport = "";
    String SizeExport = "";

    public long DataDirectory(String FileName, Long StartAdd) throws FileNotFoundException, IOException, Exception {
        RandomAccessFile access = new RandomAccessFile(FileName, "rw");
        access.seek(StartAdd);
        byte[] DHA = new byte[128];
        access.read(DHA);
        int cur = 0;
        System.out.println("export");
        SExport = DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        SizeExport = DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("import");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("resource");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("exception");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("security");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("basereloc");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("debug");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("copyright");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("globalptr");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("tls");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("loadconfig");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("bound import");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("IAT");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("DelayImport");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("ComDescriptor");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        System.out.println("Entries");
        DosHeaderPrintDw("VirtualAddress", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Size", cur, DHA);
        cur += 4;
        return StartAdd + cur;
    }
    public int SSOOH = 0;//int size of optional header;

    public long OptionalHeader(String FileName, Long StartAdd) throws FileNotFoundException, IOException, Exception {
        RandomAccessFile access = new RandomAccessFile(FileName, "rw");
        access.seek(StartAdd);
        int size = Integer.decode("0x" + SOOH);
        byte[] DHA = new byte[size];
        SSOOH = size;
        System.out.println(SOOH);
        access.read(DHA);
        //TODO
        int cur = 0;
        DosHeaderPrintw("Magic", cur, DHA);
        cur += 2;
        DosHeaderPrintb("MajorLinkerVersion", cur, DHA);
        cur += 1;
        DosHeaderPrintb("MinorLinkerVersion", cur, DHA);
        cur += 1;
        DosHeaderPrintDw("Size Of Code", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Size Of initialized data", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Size Of uninitialized data", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Address of Entry Point", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Base Of code", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Base of Data", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Image Base", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Section Allignment", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("File Allignment", cur, DHA);
        cur += 4;
        DosHeaderPrintw("MajorOperatingSystemVersion", cur, DHA);
        cur += 2;
        DosHeaderPrintw("MionorOperatingSystemVersion", cur, DHA);
        cur += 2;
        DosHeaderPrintw("MajorImageVersion", cur, DHA);
        cur += 2;
        DosHeaderPrintw("MinorImageVersion", cur, DHA);
        cur += 2;
        DosHeaderPrintw("MajorsubSystemVersion", cur, DHA);
        cur += 2;
        DosHeaderPrintw("MinorsubSystemVersion", cur, DHA);
        cur += 2;
        DosHeaderPrintDw("win32version Value", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("sizeof Image", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Size Of Header", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Check Sum", cur, DHA);
        cur += 4;
        DosHeaderPrintw("Subsystem", cur, DHA);
        cur += 2;
        DosHeaderPrintw("DLL characteristic", cur, DHA);
        cur += 2;
        DosHeaderPrintDw("SizeOfStackreserve", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("SizeOf Stack commit", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Size Of heap reserve", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Size Of heap commit", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Loaderflag", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Number of RVA and Sizes", cur, DHA);
        cur += 4;
        return StartAdd + size - 128;
    }
    public String SOOH = "";//Size of Optional Header
    public String NOS = ""; //number of sections;

    public long FileHeader(String FileName, Long StartAdd) throws FileNotFoundException, IOException, Exception {
        RandomAccessFile access = new RandomAccessFile(FileName, "rw");
        access.seek(StartAdd);
        //System.out.println(StartAdd);
        byte[] DHA = new byte[20];
        access.read(DHA);
        int cur = 0;
        DosHeaderPrintw("Machine", cur, DHA);
        cur += 2;
        NOS = DosHeaderPrintw("Number Of Section", cur, DHA);
        cur += 2;
        DosHeaderPrintDw("Time Date Stamp", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Pointer To Symbol Table", cur, DHA);
        cur += 4;
        DosHeaderPrintDw("Number Of Symbol", cur, DHA);
        cur += 4;
        SOOH = DosHeaderPrintw("Size Of Optional Header", cur, DHA);
        cur += 2;
        DosHeaderPrintw("Characteristic", cur, DHA);
        cur += 2;
        System.out.println("---------");
        return StartAdd + 20;



    }

    public long PE(String FileName, String StartAdd) throws FileNotFoundException, IOException, Exception {
        int decode = Integer.decode("0x" + StartAdd);
        //System.out.println(decode);
        RandomAccessFile access = new RandomAccessFile(FileName, "rw");
        access.seek(decode);
        byte[] b = new byte[4];
        access.read(b);
        String Sword = byteArrayToHexString(b);
        System.out.print("Signature :");
        System.out.println(Reverse(Sword));

        return decode + 4;
    }

    public String DosHeader(String FileName) throws FileNotFoundException, IOException, Exception {


        byte[] DHA = new byte[64];
        int cur = 0;
        FileInputStream f = new FileInputStream(FileName);
        InputStream fi = new BufferedInputStream(f);
        fi.read(DHA);
        byte[] Dword = new byte[4];
        System.arraycopy(DHA, 60, Dword, 0, 4);
        String Sword = byteArrayToHexString(Dword);
        System.out.print("IFANEW" + ":");
        System.out.println(Reverse(Sword));
        System.out.println("--------------------");
        return Reverse(Sword);
    }

    private String DosHeaderPrintb(String Name, int cur, byte[] DHA) throws Exception {
        byte[] word = new byte[1];
        System.arraycopy(DHA, cur, word, 0, 1);
        String Sword = byteArrayToHexString(word);
        System.out.print(Name + ":");
        System.out.println(Reverse(Sword));
        return Reverse(Sword);
    }

    private String DosHeaderPrintw(String Name, int cur, byte[] DHA) throws Exception {
        byte[] word = new byte[2];
        System.arraycopy(DHA, cur, word, 0, 2);
        String Sword = byteArrayToHexString(word);
        System.out.print(Name + ":");
        System.out.println(Reverse(Sword));
        return Reverse(Sword);
    }

    private String DosHeaderPrintDw(String Name, int cur, byte[] DHA) throws Exception {
        byte[] Dword = new byte[4];
        System.arraycopy(DHA, cur, Dword, 0, 4);
        String Sword = byteArrayToHexString(Dword);
        if (Name.compareTo("NOTU") != 0) {
            System.out.print(Name + ":");
            System.out.println(Reverse(Sword));
        }
        return Reverse(Sword);
    }

    private String NRDosHeaderPrintD1(String Name, int cur, byte[] DHA) throws Exception {
        byte[] Dword = new byte[1];
        System.arraycopy(DHA, cur, Dword, 0, 1);
        String Sword = byteArrayToHexString(Dword);
        return (Sword);
    }
}

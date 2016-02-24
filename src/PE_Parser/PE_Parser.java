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
import java.util.logging.Level;
import java.util.logging.Logger;

public class PE_Parser {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws IOException {

        Header h = new Header();
        try {
            h.SetFile("test.dll");
            h.Show();
        } catch (FileNotFoundException ex) {
            System.out.print("NOT FOUND");
            Logger.getLogger(PE_Parser.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(PE_Parser.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}

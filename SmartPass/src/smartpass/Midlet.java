/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package smartpass;

import javax.microedition.lcdui.Command;
import javax.microedition.lcdui.CommandListener;
import javax.microedition.lcdui.Display;
import javax.microedition.lcdui.Displayable;
import javax.microedition.midlet.*;

/**
 * @author aduarte
 */
public class Midlet extends MIDlet implements CommandListener {

    private Command exitCommand;

    public void startApp() {
        exitCommand = new Command("Salir", Command.EXIT, 0);


        TokenCanvas tokenCanvas = new TokenCanvas();

        tokenCanvas.setCommandListener(this);

        Display display = Display.getDisplay(this);
        tokenCanvas.start();
        tokenCanvas.addCommand(exitCommand);
        display.setCurrent(tokenCanvas);
   }

    public void commandAction(Command command, Displayable displayable) {
        if (command == exitCommand) {
            exitMIDlet();
        }
    }

    public void pauseApp() {
    }

    public void destroyApp(boolean unconditional) {
    }

    public void exitMIDlet() {
        destroyApp(true);
        notifyDestroyed();
    }
}

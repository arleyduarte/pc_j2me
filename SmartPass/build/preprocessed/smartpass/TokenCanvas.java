/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package smartpass;

import java.util.Date;
import javax.microedition.lcdui.Font;
import javax.microedition.lcdui.Graphics;
import javax.microedition.lcdui.Image;
import javax.microedition.lcdui.game.GameCanvas;

/**
 *
 * @author aduarte
 */
public class TokenCanvas extends GameCanvas implements Runnable {

    private TOTPGenerator totpGenerator = new TOTPGenerator("MFRGGZDFMZUGO2LK");

    public TokenCanvas() {
        super(true);
         getBackRectangle();
         getLogo();

    }

    public void run() {

        Graphics g = getGraphics();

        while (true) {

            updateTokenScreen(g);

            try {
                Thread.currentThread().sleep(3000);
            } catch (InterruptedException ex) {
                ex.printStackTrace();
            }
        }

    }

    public void start() {
        Thread runner = new Thread(this);
        runner.start();
    }
    private static final int BACKGROUND_COLOR = 0xDAD6CF;

    private void updateTokenScreen(Graphics g) {
        //clear background
        g.setColor(BACKGROUND_COLOR);
        g.fillRect(0, 0, getWidth(), getHeight());


        Date horaActual = new Date(System.currentTimeMillis());

        String otp = totpGenerator.computeOTP(horaActual);

       
        int xposition = getWidth() / 2 - imgRectangle.getWidth() / 2;
        int ypossiton = getHeight() / 2 - imgRectangle.getHeight() / 2;

        g.drawImage(imgRectangle, xposition, ypossiton, 20);
        g.setColor(0x000000);
        g.setFont(Font.getFont(Font.FACE_MONOSPACE, Font.STYLE_BOLD, Font.SIZE_LARGE));
        g.drawString(otp, getWidth() / 2, getHeight() / 2, Graphics.HCENTER | Graphics.BASELINE);
        
        int xCenterLogo = getWidth() / 2 - imgLogo.getWidth() / 2;
        
        g.drawImage(imgLogo, xCenterLogo, 10, 20);



        System.out.println(otp);
        flushGraphics();
    }
    private Image imgRectangle;

    public Image getBackRectangle() {
        if (imgRectangle == null) {

            try {
                imgRectangle = Image.createImage("/resource/rect.png");
            } catch (java.io.IOException e) {
                e.printStackTrace();
            }

        }
        return imgRectangle;
    }
    
    private Image imgLogo;

    public Image getLogo() {
        if (imgLogo == null) {

            try {
                imgLogo = Image.createImage("/resource/logo.png");
            } catch (java.io.IOException e) {
                e.printStackTrace();
            }

        }
        return imgLogo;
    }    
}

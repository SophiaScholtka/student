package de.tubs.cs.iti.krypto.protokoll;

import java.awt.*;
import java.awt.event.*;
/**
 * PopWindow zur Ausgabe von Fehlermeldungen.
 * Diese Klasse erzeugt ein Fenster mit entweder einem "Ja" und einem "Nein" Button,
 * oder nur einem "OK" Button.
 * Das Fenster schliesst sich nach dem einer der Button gedrueckt wurde.
 * @author Marcus Lagemann
 * @version 0.1
 */

public class popUpWindow extends Dialog {
    boolean result;

    /**
     * Der Konstruktor erzeugt ein Fenster mit dem String text als Text, einem
     * und einem "Ok" Button.
     * @param owner "Besitzer" des PopUpFensters
     * @param text Text der im popUpFensters erscheinen soll
     * @param ok unterscheidet den Konstruktor vom "Ja"-"Nein"-"popUpWindow"
     */
    public popUpWindow( Frame owner, String text, boolean ok ) {
        super( owner, "Dialog", true );
        setLayout( new BorderLayout() );
        setBackground( new Color( 0, 118, 184 ) );
        setForeground( new Color( 0, 0, 0 ) );
        setFont( new Font( "SansSerif", 1, 14 ) );
        setResizable( false );

        add( "Center", new Label( text, 1 ) );

        Panel panel = new Panel();
        panel.setLayout( new FlowLayout( FlowLayout.CENTER ) );
        Button button = new Button( "OK" );
        button.setBackground( new Color( 0, 118, 184 ) );

        button.addActionListener( new java.awt.event.ActionListener() {
                                      public void actionPerformed( ActionEvent e ) {
                                          result = true;
                                          setVisible( false );
                                          dispose();
                                      }
                                  }

                                );

        panel.add( button );
        add( "South", panel );
        pack();
        setLocation( owner.getX() + owner.getWidth() / 2 - getWidth() / 2,
                     owner.getY() + owner.getHeight() / 2 - getHeight() / 2 );
        setVisible( true );
    }


    /**
     * Der Konstruktor erzeugt ein Fenster mit dem String text als Text, einem
     * "Ja" Button und einem "Nein" Button.
     * @param owner "Besitzer" des PopUpFensters
     * @param text Text der im popUpFensters erscheinen soll
     */
    public popUpWindow( Frame owner, String text ) {
        super( owner, "Dialog", true );
        setLayout( new BorderLayout() );
        setBackground( new Color( 0, 118, 184 ) );
        setForeground( new Color( 0, 0, 0 ) );
        setFont( new Font( "SansSerif", 1, 14 ) );
        setResizable( false );

        add( "Center", new Label( text, 1 ) );

        Panel panel = new Panel();
        panel.setLayout( new FlowLayout( FlowLayout.CENTER ) );
        Button button = new Button( "Ja" );
        button.setBackground( new Color( 0, 118, 184 ) );

        button.addActionListener( new java.awt.event.ActionListener() {
                                      public void actionPerformed( ActionEvent e ) {
                                          result = true;
                                          setVisible( false );
                                          dispose();
                                      }
                                  }

                                );

        panel.add( button );
        button = new Button( "Nein" );
        button.setBackground( new Color( 0, 118, 184 ) );

        button.addActionListener( new java.awt.event.ActionListener() {
                                      public void actionPerformed( ActionEvent e ) {
                                          result = false;
                                          setVisible( false );
                                          dispose();
                                      }
                                  }

                                );

        panel.add( button );

        add( "South", panel );
        pack();
        setLocation( owner.getX() + owner.getWidth() / 2 - getWidth() / 2,
                     owner.getY() + owner.getHeight() / 2 - getHeight() / 2 );
        setVisible( true );
    }

    /**
     * Die Methode gibt den Wert des Attributs result zurueck. Sie ist "true", wenn der
     * "Ja"-Button gedrueckt wurde. Ansonsten ist sie "false".
     */
    public boolean getResult() {
        return result;
    }

}

// $Log: popUpWindow.java,v $
// Revision 1.4  2001/07/03 18:22:54  y0013155
// RoughNetz.zip added
// contains class files, instructions and sources
// Marco
//
// Revision 1.3  2001/07/02 21:08:16  y0013406
// changed comments and tex-files
//
// Revision 1.2  2001/07/01 18:23:58  y0013406
// Added Constructor with one OK button
//
// Revision 1.1  2001/06/27 18:27:10  y0013406
// new class for popUpWindows
//

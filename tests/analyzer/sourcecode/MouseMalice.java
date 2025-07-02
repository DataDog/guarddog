/*
 * Gdańsk University of Technology - Engineering Thesis
 * Malicious Module for Netbeans
 *
 * Cilińdź Michał, Gabryelska Nela, Micał Marek
 */
package pl.gda.pg.eti.kio.malicious.entity;

import java.awt.AWTEvent;
import java.awt.EventQueue;
import java.awt.Toolkit;
import java.awt.event.AWTEventListener;
import java.awt.event.MouseEvent;
import java.util.Set;
import javax.swing.JEditorPane;
import javax.swing.text.StyledDocument;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openide.cookies.EditorCookie;
import org.openide.nodes.Node;
import org.openide.util.Exceptions;
import org.openide.windows.CloneableTopComponent;
import org.openide.windows.Mode;
import org.openide.windows.TopComponent;
import org.openide.windows.WindowManager;
import pl.gda.pg.eti.kio.malicious.annotation.CreatableMalicious;
import pl.gda.pg.eti.kio.malicious.attribute.QuantityAttribute;
import pl.gda.pg.eti.kio.malicious.event.MaliciousEvent;

/**
 *
 * @author Marek Micał
 */
@CreatableMalicious(name = "mouse_malice")
public class MouseMalice extends BaseMalice {

    private QuantityAttribute attributes;
    private int numberOfClicks;
    private final Logger log = LogManager.getLogger(MouseMalice.class);
    private String name = getClass().getSimpleName();
    //ruleid: maven-event-listening
    AWTEventListener doubleClickListener = new AWTEventListener() {
        @Override
        public void eventDispatched(AWTEvent event) {
            if (event instanceof MouseEvent) {
                MouseEvent evt = (MouseEvent) event;
                if (evt.getID() == MouseEvent.MOUSE_RELEASED) {
                    if (evt.getClickCount() == 1 && !evt.isConsumed()) {
                        numberOfClicks = 1;
                        processClick();
                    }

                    if (evt.getClickCount() == 2 && !evt.isConsumed()) {
                        evt.consume();
                        numberOfClicks = 2;
                        processClick();
                    }
                }
            }
        }
    };
    private final Runnable mouseMaliceThread = new Runnable() {
        @Override
        public void run() {
            Node[] n = TopComponent.getRegistry().getActivatedNodes();

            if (n.length == 1) {

                EditorCookie ec = (EditorCookie) n[0].getLookup().lookup(EditorCookie.class);
                if (ec != null) {
                    JEditorPane[] panes = ec.getOpenedPanes();

                    if (panes != null && panes.length > 0) {
                        if (numberOfClicks == 1) {
                            manipulateCaret(panes[0]);
                        }
                        if (numberOfClicks == 2) {
                            dockEditorPane();
                        }
                    }
                }

            }
        }
    };

    private void initializeAttributes() {
        String frequency = (String) (super.getParameter("frequency"));
        if ((frequency != null) && (!frequency.isEmpty()) && frequency.matches("\\d*-\\d*")) {
            attributes = new QuantityAttribute(frequency);
        } else {
            attributes = new QuantityAttribute(0, 1);
        }
        attributes.addCounter("click");
        attributes.addCounter("doubleclick");
        attributes.addCounter("selection");
    }

    public void setAttributes(QuantityAttribute attributes) {
        this.attributes = attributes;
    }
    
    

    public void processClick() {
        new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException ex) {
                    Exceptions.printStackTrace(ex);
                }
                EventQueue.invokeLater(mouseMaliceThread);
            }
        }.run();

    }

    private void manipulateCaret(JEditorPane editorPane) {
        StyledDocument doc = (StyledDocument) editorPane.getDocument();
        String selectedText = editorPane.getSelectedText();
        if (selectedText == null || selectedText.length() == 0) {
            if (attributes.checkCounter("click")) {
                editorPane.setCaretPosition((int) (Math.random() * doc.getLength()));
                log.info("Completed: {} - {}", name, "ManipulateCaret completed successfully");
            }
        } else {
            if (attributes.checkCounter("selection")) {
                int rand1 = (int) (Math.random() * doc.getLength());
                int rand2 = (int) (Math.random() * doc.getLength());
                editorPane.setSelectionStart(rand1);
                editorPane.setSelectionEnd(rand2 > rand1 ? rand2 : (rand2 - rand1) + rand1);
                log.info("Completed: {} - {}", name, "ManipulateSelection completed successfully");
            }
        }
    }

    private void dockEditorPane() {
        if (attributes.checkCounter("doubleclick")) {
            try {
                Set<TopComponent> tcs = TopComponent.getRegistry().getOpened();
                TopComponent source = null;
                for (TopComponent t : tcs) {
                    if (t instanceof CloneableTopComponent) {
                        source = t;
                    }
                }
                WindowManager m = WindowManager.getDefault();
                String mode = "";
                int rand = (int) (Math.random() * 4);
                if (rand == 0 || rand == 3) {
                    mode = "explorer";
                }
                if (rand == 1 || rand == 4) {
                    mode = "output";
                }
                if (rand == 2) {
                    mode = "navigator";
                }
                Mode explorer = m.findMode(mode);
                explorer.dockInto(source);
                log.info("Completed: {} - {}", name, "DockEditorPane completed successfully");
            } catch (Exception ex) {
                log.error("DockEditorPane completed unsuccessfully", ex);
            }
        }
    }

    @Override
    protected void execute(MaliciousEvent event) {
        this.initializeAttributes();
        Toolkit.getDefaultToolkit().addAWTEventListener(doubleClickListener, AWTEvent.MOUSE_EVENT_MASK);
    }
}
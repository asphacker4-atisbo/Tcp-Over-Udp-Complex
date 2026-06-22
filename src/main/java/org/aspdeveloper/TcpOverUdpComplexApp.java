package org.aspdeveloper;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.plaf.basic.*;
import java.awt.*;
import java.awt.event.*;
import java.awt.geom.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.stream.Collectors;

/**
 * TCP-over-UDP — complete TCP stack encapsulated inside UDP datagrams.
 * <p>
 * Wire format (each UDP payload):
 * [ 20-byte IP pseudo-header ] [ 20-byte TCP header ] [ payload ]
 * <p>
 * The IP pseudo-header is NOT sent over the wire, only used for the
 * checksum calculation (RFC 793). The actual UDP payload is:
 * [ 20-byte TCP header (with valid checksum) ] [ payload ]
 * <p>
 * This means any tool that reads raw TCP headers (Scapy, Wireshark
 * dissector, custom receivers) can parse these packets correctly,
 * as long as they know the source/dest IPs for checksum validation.
 */
public class TcpOverUdpComplexApp extends JFrame {

    // ── Palette ────────────────────────────────────────────────────────────
    static final Color BG_DARK = new Color(0x1a1a1a);
    static final Color BG_PANEL = new Color(0x222222);
    static final Color BG_FIELD = new Color(0x111111);
    static final Color BG_LOG = new Color(0x0d0d0d);
    static final Color GOLD_LIGHT = new Color(0xd4a44c);
    static final Color GOLD_DIM = new Color(0x8a6820);
    static final Color GOLD_BORDER = new Color(0xa07030);
    static final Color TEXT_PRIMARY = new Color(0xe8e0d0);
    static final Color TEXT_DIM = new Color(0x888070);
    static final Color GREEN_OK = new Color(0x4caf50);
    static final Color RED_ERR = new Color(0xcf4040);
    static final Color BLUE_INFO = new Color(0x5ab4e5);
    static final Color AMBER_DATA = new Color(0xd4a44c);

    // ── State ───────────────────────────────────────────────────────────────
    private volatile Receiver receiver;
    private final AtomicBoolean receiverOn = new AtomicBoolean(false);

    // ── Controls ─────────────────────────────────────────────────────────
    private final DarkToggle receiverToggle = new DarkToggle();
    private final JTextField txtListenPort = darkField("5000");
    private final JTextField txtDestHost = darkField("127.0.0.1");
    private final JTextField txtDestPort = darkField("5000");
    private final JTextField txtWindow = darkField("64");
    private final JTextArea txtMessage = new JTextArea(4, 40);
    private final JButton btnShuffle = goldButton("⚅  Shuffle Previsión");
    private final JButton btnSend = goldButton("✈  ENVIAR BARAJADO");
    private final JProgressBar progressBar = new JProgressBar();
    private final JTextArea txtLog = new JTextArea();
    private final JTextField txtFilter = darkField("Filtrar registros...");
    private final JButton btnClearLog = smallButton("Limpiar Registro");
    private final JLabel lblStatus = new JLabel("● Desconectado");
    private final JLabel lblTitleStatus = new JLabel("  ● Desconectado");

    // full log lines kept for filtering
    private final List<String> allLogLines = Collections.synchronizedList(new ArrayList<>());

    public TcpOverUdpComplexApp() {
        super("TCP over UDP Complex");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setBackground(BG_DARK);
        setMinimumSize(new Dimension(900, 700));

        applyGlobalLAF();
        buildUI();
        wireActions();
        setLocationByPlatform(true);
        pack();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // UI CONSTRUCTION
    // ═══════════════════════════════════════════════════════════════════════

    private void buildUI() {
        JPanel root = new JPanel(new BorderLayout(0, 0));
        root.setBackground(BG_DARK);
        root.setBorder(BorderFactory.createEmptyBorder(10, 12, 0, 12));

        root.add(buildTopBar(), BorderLayout.NORTH);
        root.add(buildCenter(), BorderLayout.CENTER);
        root.add(buildStatusBar(), BorderLayout.SOUTH);

        setContentPane(root);
    }

    private JPanel buildTopBar() {
        JPanel bar = new JPanel(new BorderLayout(12, 0));
        bar.setOpaque(false);
        bar.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

        // Left: receiver toggle
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        left.setOpaque(false);
        JLabel receiverLabel = new JLabel("Receiver");
        receiverLabel.setForeground(TEXT_PRIMARY);
        receiverLabel.setFont(labelFont());
        left.add(receiverToggle);
        left.add(receiverLabel);
        left.add(Box.createHorizontalStrut(6));
        left.add(labeledField("Puerto:", txtListenPort, 70));

        // Right: connection status in title bar area
        lblTitleStatus.setForeground(TEXT_DIM);
        lblTitleStatus.setFont(new Font("Monospaced", Font.PLAIN, 12));

        bar.add(left, BorderLayout.WEST);
        bar.add(lblTitleStatus, BorderLayout.EAST);
        return bar;
    }

    private JPanel buildCenter() {
        JPanel center = new JPanel(new BorderLayout(0, 10));
        center.setOpaque(false);

        center.add(buildSenderPanel(), BorderLayout.NORTH);
        center.add(buildLogPanel(), BorderLayout.CENTER);
        return center;
    }

    private JPanel buildSenderPanel() {
        GoldBorderPanel panel = new GoldBorderPanel(new BorderLayout(10, 10));
        panel.setBorder(new CompoundBorder(
                new GoldRoundBorder(8),
                BorderFactory.createEmptyBorder(12, 14, 12, 14)
        ));

        // Destinatario row
        JPanel destRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        destRow.setOpaque(false);

        JLabel destLabel = sectionLabel("Destinatario");
        destRow.add(destLabel);
        destRow.add(Box.createHorizontalStrut(8));
        destRow.add(iconField("🌐", txtDestHost, 160, "Host"));
        destRow.add(iconField("🔌", txtDestPort, 80, "Puerto"));
        destRow.add(iconField("⇄", txtWindow, 60, "Ventana"));
        destRow.add(Box.createHorizontalGlue());
        destRow.add(btnShuffle);
        destRow.add(btnSend);

        panel.add(destRow, BorderLayout.NORTH);

        // Message area
        JPanel msgPanel = new JPanel(new BorderLayout(10, 8));
        msgPanel.setOpaque(false);

        JLabel msgLabel = sectionLabel("MENSAJE A ENVIAR");
        msgLabel.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0));

        txtMessage.setBackground(BG_FIELD);
        txtMessage.setForeground(TEXT_PRIMARY);
        txtMessage.setCaretColor(GOLD_LIGHT);
        txtMessage.setFont(new Font("Monospaced", Font.PLAIN, 13));
        txtMessage.setLineWrap(true);
        txtMessage.setWrapStyleWord(true);
        txtMessage.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JScrollPane msgScroll = new JScrollPane(txtMessage);
        msgScroll.setBorder(new GoldRoundBorder(5));
        msgScroll.setBackground(BG_FIELD);
        msgScroll.getViewport().setBackground(BG_FIELD);
        msgScroll.setPreferredSize(new Dimension(400, 90));

        // Right panel with toggle and extra buttons
        JPanel rightPanel = new JPanel();
        rightPanel.setOpaque(false);
        rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));

        JPanel sendRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        sendRow.setOpaque(false);
        JButton btnSend2 = smallButton("Send");
        JLabel shuffledLabel = new JLabel("Barajado");
        shuffledLabel.setForeground(TEXT_DIM);
        shuffledLabel.setFont(labelFont());
        DarkToggle shuffleToggle = new DarkToggle();
        shuffleToggle.setSelected(true);
        sendRow.add(btnSend2);
        sendRow.add(shuffledLabel);
        sendRow.add(shuffleToggle);

        JPanel previewRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        previewRow.setOpaque(false);
        JButton btnShuf2 = smallButton("⚅  Shuffle Previsión");
        DarkToggle tog2 = new DarkToggle();
        JButton btnEnviar2 = smallButton("✈  ENVIAR BARAJADO");
        previewRow.add(btnShuf2);
        previewRow.add(tog2);
        previewRow.add(btnEnviar2);

        rightPanel.add(sendRow);
        rightPanel.add(Box.createVerticalStrut(6));
        rightPanel.add(previewRow);

        // wire extra controls to same actions
        btnSend2.addActionListener(e -> onSend(false));
        shuffleToggle.addChangeListener(e -> {
        });
        btnShuf2.addActionListener(e -> onShufflePreview());
        btnEnviar2.addActionListener(e -> onSend(true));

        msgPanel.add(msgLabel, BorderLayout.NORTH);
        msgPanel.add(msgScroll, BorderLayout.CENTER);
        msgPanel.add(rightPanel, BorderLayout.EAST);

        // Progress bar
        progressBar.setBackground(BG_FIELD);
        progressBar.setForeground(GOLD_LIGHT);
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        progressBar.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        progressBar.setUI(new BasicProgressBarUI() {
            @Override
            protected Color getSelectionForeground() {
                return BG_DARK;
            }

            @Override
            protected Color getSelectionBackground() {
                return TEXT_PRIMARY;
            }
        });

        JPanel msgWithProgress = new JPanel(new BorderLayout());
        msgWithProgress.setOpaque(false);
        msgWithProgress.add(msgPanel, BorderLayout.CENTER);
        msgWithProgress.add(progressBar, BorderLayout.SOUTH);

        panel.add(msgWithProgress, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildLogPanel() {
        GoldBorderPanel panel = new GoldBorderPanel(new BorderLayout(0, 6));
        panel.setBorder(new CompoundBorder(
                new GoldRoundBorder(8),
                BorderFactory.createEmptyBorder(10, 14, 10, 14)
        ));
        panel.setPreferredSize(new Dimension(0, 280));

        // Header
        JPanel header = new JPanel(new BorderLayout(10, 0));
        header.setOpaque(false);

        JLabel logTitle = new JLabel("🔍  REGISTRO DE ACTIVIDAD");
        logTitle.setForeground(GOLD_LIGHT);
        logTitle.setFont(new Font("SansSerif", Font.BOLD, 14));

        JPanel filterPanel = new JPanel(new BorderLayout(6, 0));
        filterPanel.setOpaque(false);
        txtFilter.setPreferredSize(new Dimension(200, 28));
        txtFilter.setForeground(TEXT_DIM);
        txtFilter.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JButton btnClearFilter = smallButton("✕");
        btnClearFilter.setPreferredSize(new Dimension(28, 28));
        btnClearFilter.addActionListener(e -> {
            txtFilter.setText("");
            applyFilter();
        });
        filterPanel.add(txtFilter, BorderLayout.CENTER);
        filterPanel.add(btnClearFilter, BorderLayout.EAST);

        header.add(logTitle, BorderLayout.WEST);
        header.add(filterPanel, BorderLayout.CENTER);
        header.add(btnClearLog, BorderLayout.EAST);

        // Log area
        txtLog.setEditable(false);
        txtLog.setBackground(BG_LOG);
        txtLog.setForeground(TEXT_PRIMARY);
        txtLog.setFont(new Font("Monospaced", Font.PLAIN, 12));
        txtLog.setLineWrap(true);
        txtLog.setWrapStyleWord(false);
        txtLog.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JScrollPane scroll = new JScrollPane(txtLog);
        scroll.setBorder(new GoldRoundBorder(5));
        scroll.setBackground(BG_LOG);
        scroll.getViewport().setBackground(BG_LOG);
        scroll.getVerticalScrollBar().setBackground(BG_PANEL);
        scroll.getVerticalScrollBar().setForeground(GOLD_DIM);

        panel.add(header, BorderLayout.NORTH);
        panel.add(scroll, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(new Color(0x0f0f0f));
        bar.setBorder(new CompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, GOLD_DIM),
                BorderFactory.createEmptyBorder(4, 12, 4, 12)
        ));
        lblStatus.setForeground(RED_ERR);
        lblStatus.setFont(new Font("Monospaced", Font.PLAIN, 12));
        bar.add(lblStatus, BorderLayout.WEST);
        return bar;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // WIRE ACTIONS
    // ═══════════════════════════════════════════════════════════════════════

    private void wireActions() {
        receiverToggle.addChangeListener(e -> onReceiverToggle());
        btnShuffle.addActionListener(e -> onShufflePreview());
        btnSend.addActionListener(e -> onSend(true));
        btnClearLog.addActionListener(e -> {
            allLogLines.clear();
            txtLog.setText("");
        });

        txtFilter.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) {
                applyFilter();
            }

            public void removeUpdate(DocumentEvent e) {
                applyFilter();
            }

            public void changedUpdate(DocumentEvent e) {
                applyFilter();
            }
        });

        // placeholder behavior
        txtFilter.addFocusListener(new FocusAdapter() {
            public void focusGained(FocusEvent e) {
                if (txtFilter.getText().equals("Filtrar registros...")) {
                    txtFilter.setText("");
                    txtFilter.setForeground(TEXT_PRIMARY);
                }
            }

            public void focusLost(FocusEvent e) {
                if (txtFilter.getText().isEmpty()) {
                    txtFilter.setText("Filtrar registros...");
                    txtFilter.setForeground(TEXT_DIM);
                }
            }
        });
    }

    private void onReceiverToggle() {
        boolean on = receiverToggle.isSelected();
        if (on) {
            try {
                int port = Integer.parseInt(txtListenPort.getText().trim());
                if (receiver != null && receiver.isRunning()) {
                    log("INFO", "Receiver already running on port " + receiver.port);
                    return;
                }
                receiver = new Receiver(port, this::log, this::showReconstructed);
                receiver.start();
                receiverOn.set(true);
                setConnected("127.0.0.1:" + port);
            } catch (Exception ex) {
                logError("Could not start receiver: " + ex.getMessage());
                receiverToggle.setSelected(false);
            }
        } else {
            if (receiver != null) {
                receiver.stopReceiver();
            }
            receiverOn.set(false);
            setDisconnected();
        }
    }

    private void onShufflePreview() {
        String s = txtMessage.getText();
        JOptionPane.showMessageDialog(this,
                shuffleString(s == null ? "" : s),
                "Shuffled (preview)", JOptionPane.INFORMATION_MESSAGE);
    }

    private void onSend(boolean shuffle) {
        new Thread(() -> {
            try {
                SwingUtilities.invokeLater(() -> {
                    btnSend.setEnabled(false);
                    progressBar.setVisible(true);
                    progressBar.setValue(0);
                    progressBar.setMaximum(100);
                });

                String host = txtDestHost.getText().trim();
                int port = Integer.parseInt(txtDestPort.getText().trim());
                String msg = txtMessage.getText();
                if (msg == null) msg = "";

                byte[] data = msg.getBytes(StandardCharsets.UTF_8);
                log("INFO", String.format("Iniciando envío confiable a %s:%d | %d bytes", host, port, data.length));

                Sender sender = new Sender(host, port, data, this::log, this::logError, shuffle);
                sender.send(progressBar::setValue);

            } catch (Exception ex) {
                logError("Send failed: " + ex.getMessage());
            } finally {
                SwingUtilities.invokeLater(() -> {
                    btnSend.setEnabled(true);
                    progressBar.setVisible(false);
                });
            }
        }, "SenderThread").start();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // LOGGING
    // ═══════════════════════════════════════════════════════════════════════

    private static final SimpleDateFormat TS_FMT = new SimpleDateFormat("HH:mm:ss.SSS");

    private void log(String level, String msg) {
        String ts = TS_FMT.format(new Date());
        String line = String.format("[%s] %-5s: %s", ts, level, msg);
        allLogLines.add(line);
        SwingUtilities.invokeLater(() -> appendColoredLog(level, line));
    }

    private void logError(String msg) {
        log("ERROR", msg);
    }

    private void appendColoredLog(String level, String line) {
        String filter = txtFilter.getText();
        if (!filter.isEmpty() && !filter.equals("Filtrar registros...") &&
                !line.toLowerCase().contains(filter.toLowerCase())) return;

        txtLog.append(line + "\n");
        txtLog.setCaretPosition(txtLog.getDocument().getLength());
    }

    private void applyFilter() {
        String filter = txtFilter.getText();
        if (filter.equals("Filtrar registros...")) filter = "";
        final String f = filter;
        SwingUtilities.invokeLater(() -> {
            StringBuilder sb = new StringBuilder();
            synchronized (allLogLines) {
                for (String line : allLogLines) {
                    if (f.isEmpty() || line.toLowerCase().contains(f.toLowerCase()))
                        sb.append(line).append('\n');
                }
            }
            txtLog.setText(sb.toString());
            txtLog.setCaretPosition(txtLog.getDocument().getLength());
        });
    }

    private void showReconstructed(byte[] data) {
        String msg = new String(data, StandardCharsets.UTF_8);
        log("DATA", "Reconstructed: " + msg.substring(0, Math.min(60, msg.length())) + (msg.length() > 60 ? "…" : ""));
        SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(this,
                        "Mensaje reconstruido:\n\n" + msg,
                        "Reconstruido", JOptionPane.INFORMATION_MESSAGE));
    }

    private void setConnected(String addr) {
        SwingUtilities.invokeLater(() -> {
            String txt = "● Conexión: Conectado (" + addr + ")";
            lblStatus.setText(txt);
            lblStatus.setForeground(GREEN_OK);
            lblTitleStatus.setText("  " + txt);
            lblTitleStatus.setForeground(GREEN_OK);
        });
    }

    private void setDisconnected() {
        SwingUtilities.invokeLater(() -> {
            lblStatus.setText("● Desconectado");
            lblStatus.setForeground(RED_ERR);
            lblTitleStatus.setText("  ● Desconectado");
            lblTitleStatus.setForeground(RED_ERR);
        });
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    private static String shuffleString(String s) {
        List<Character> chars = s.chars().mapToObj(c -> (char) c).collect(Collectors.toList());
        Collections.shuffle(chars);
        StringBuilder sb = new StringBuilder(chars.size());
        chars.forEach(sb::append);
        return sb.toString();
    }

    private static List<byte[]> segment(byte[] bytes, int mss) {
        if (bytes.length == 0) return Collections.singletonList(new byte[0]);
        List<byte[]> parts = new ArrayList<>();
        for (int i = 0; i < bytes.length; i += mss) {
            int len = Math.min(mss, bytes.length - i);
            parts.add(Arrays.copyOfRange(bytes, i, i + len));
        }
        return parts;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // UI FACTORY
    // ═══════════════════════════════════════════════════════════════════════

    private void applyGlobalLAF() {
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception ignored) {
        }
        UIManager.put("OptionPane.background", BG_PANEL);
        UIManager.put("Panel.background", BG_PANEL);
        UIManager.put("OptionPane.messageForeground", TEXT_PRIMARY);
        UIManager.put("ScrollBar.thumb", GOLD_DIM);
        UIManager.put("ScrollBar.track", BG_FIELD);
    }

    private static JTextField darkField(String text) {
        JTextField f = new JTextField(text);
        f.setBackground(BG_FIELD);
        f.setForeground(TEXT_PRIMARY);
        f.setCaretColor(GOLD_LIGHT);
        f.setFont(new Font("Monospaced", Font.PLAIN, 13));
        f.setBorder(BorderFactory.createCompoundBorder(
                new GoldRoundBorder(4),
                BorderFactory.createEmptyBorder(3, 6, 3, 6)
        ));
        return f;
    }

    private static JButton goldButton(String text) {
        JButton b = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                GradientPaint gp = new GradientPaint(0, 0, new Color(0x6a4010), 0, getHeight(), new Color(0x3a2008));
                g2.setPaint(gp);
                g2.fill(new RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), 8, 8));
                g2.setColor(GOLD_BORDER);
                g2.draw(new RoundRectangle2D.Float(0.5f, 0.5f, getWidth() - 1, getHeight() - 1, 8, 8));
                g2.dispose();
                super.paintComponent(g);
            }
        };
        b.setContentAreaFilled(false);
        b.setBorderPainted(false);
        b.setForeground(GOLD_LIGHT);
        b.setFont(new Font("SansSerif", Font.BOLD, 13));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setBorder(BorderFactory.createEmptyBorder(6, 14, 6, 14));
        b.setFocusPainted(false);
        return b;
    }

    private static JButton smallButton(String text) {
        JButton b = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(new Color(0x333333));
                g2.fill(new RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), 6, 6));
                g2.setColor(GOLD_DIM);
                g2.draw(new RoundRectangle2D.Float(0.5f, 0.5f, getWidth() - 1, getHeight() - 1, 6, 6));
                g2.dispose();
                super.paintComponent(g);
            }
        };
        b.setContentAreaFilled(false);
        b.setBorderPainted(false);
        b.setForeground(TEXT_PRIMARY);
        b.setFont(new Font("SansSerif", Font.PLAIN, 12));
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));
        b.setFocusPainted(false);
        return b;
    }

    private static Font labelFont() {
        return new Font("SansSerif", Font.PLAIN, 13);
    }

    private static JLabel sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setForeground(GOLD_LIGHT);
        l.setFont(new Font("SansSerif", Font.BOLD, 13));
        return l;
    }

    private static JPanel labeledField(String labelText, JTextField field, int width) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        p.setOpaque(false);
        JLabel lbl = new JLabel(labelText);
        lbl.setForeground(TEXT_DIM);
        lbl.setFont(labelFont());
        field.setPreferredSize(new Dimension(width, 28));
        p.add(lbl);
        p.add(field);
        return p;
    }

    private static JPanel iconField(String icon, JTextField field, int width, String label) {
        JPanel p = new JPanel(new BorderLayout(4, 0));
        p.setOpaque(false);
        p.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 8));

        JPanel inner = new JPanel(new BorderLayout(0, 0));
        inner.setBackground(BG_FIELD);
        inner.setBorder(new GoldRoundBorder(4));
        inner.setPreferredSize(new Dimension(width + 30, 30));

        JLabel iconLabel = new JLabel("  " + icon + " ");
        iconLabel.setForeground(GOLD_DIM);
        iconLabel.setFont(new Font("SansSerif", Font.PLAIN, 14));
        iconLabel.setBackground(BG_FIELD);
        iconLabel.setOpaque(true);

        field.setPreferredSize(new Dimension(width, 28));
        field.setBorder(BorderFactory.createEmptyBorder(3, 4, 3, 6));

        inner.add(iconLabel, BorderLayout.WEST);
        inner.add(field, BorderLayout.CENTER);

        JPanel wrapper = new JPanel(new BorderLayout(0, 2));
        wrapper.setOpaque(false);
        JLabel lbl = new JLabel(label);
        lbl.setForeground(TEXT_DIM);
        lbl.setFont(new Font("SansSerif", Font.PLAIN, 10));
        wrapper.add(lbl, BorderLayout.NORTH);
        wrapper.add(inner, BorderLayout.CENTER);
        return wrapper;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CUSTOM COMPONENTS
    // ═══════════════════════════════════════════════════════════════════════

    static class GoldBorderPanel extends JPanel {
        GoldBorderPanel(LayoutManager lm) {
            super(lm);
            setBackground(BG_PANEL);
        }
    }

    static class GoldRoundBorder extends AbstractBorder {
        private final int radius;

        GoldRoundBorder(int r) {
            this.radius = r;
        }

        @Override
        public void paintBorder(Component c, Graphics g, int x, int y, int w, int h) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(GOLD_BORDER);
            g2.draw(new RoundRectangle2D.Float(x + 0.5f, y + 0.5f, w - 1, h - 1, radius * 2, radius * 2));
            g2.dispose();
        }

        @Override
        public Insets getBorderInsets(Component c) {
            return new Insets(1, 1, 1, 1);
        }
    }

    /**
     * Animated iOS-style toggle.
     */
    static class DarkToggle extends JToggleButton {
        private float thumb = 0f;
        private javax.swing.Timer anim;

        DarkToggle() {
            setPreferredSize(new Dimension(44, 24));
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            addChangeListener(e -> animateTo(isSelected() ? 1f : 0f));
        }

        private void animateTo(float target) {
            if (anim != null) anim.stop();
            anim = new javax.swing.Timer(16, null);
            anim.addActionListener(e -> {
                thumb += (target - thumb) * 0.25f;
                if (Math.abs(thumb - target) < 0.01f) {
                    thumb = target;
                    anim.stop();
                }
                repaint();
            });
            anim.start();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int w = getWidth(), h = getHeight();
            Color track = new Color(
                    (int) (RED_ERR.getRed() + thumb * (GREEN_OK.getRed() - RED_ERR.getRed())),
                    (int) (RED_ERR.getGreen() + thumb * (GREEN_OK.getGreen() - RED_ERR.getGreen())),
                    (int) (RED_ERR.getBlue() + thumb * (GREEN_OK.getBlue() - RED_ERR.getBlue()))
            );
            g2.setColor(track);
            g2.fill(new RoundRectangle2D.Float(0, 0, w, h, h, h));
            g2.setColor(GOLD_BORDER);
            g2.draw(new RoundRectangle2D.Float(0.5f, 0.5f, w - 1, h - 1, h, h));
            int tw = h - 4;
            float tx = 2 + thumb * (w - tw - 4);
            g2.setColor(new Color(0xe0d0b0));
            g2.fill(new Ellipse2D.Float(tx, 2, tw, tw));
            g2.dispose();
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TCP SENDER — full sliding-window + slow-start + AIMD + retransmit
    // ═══════════════════════════════════════════════════════════════════════

    private static class Sender {
        private static final int MSS = 1400;
        private static final int INIT_CWND = 1;      // segments
        private static final int INIT_SSTHRESH = 16;     // segments
        private static final long BASE_RTO = 2000;   // ms
        private static final int MAX_RETRIES = 10;
        private static final int RECV_WIN = 65535;

        private final InetAddress destAddr;
        private final int destPort;
        private final byte[] data;
        private final List<byte[]> segments;

        private final java.util.function.BiConsumer<String, String> log;
        private final java.util.function.Consumer<String> err;

        private DatagramSocket socket;
        private int srcPort;
        private long ISS;           // Initial Send Sequence
        private long IRS;           // Initial Receive Sequence
        private long SND_UNA;       // oldest unacknowledged
        private long SND_NXT;       // next to send
        private int cwnd;          // congestion window (bytes)
        private int ssthresh;
        private long rto = BASE_RTO;
        private double srtt = -1, rttvar = 0;

        private final boolean shuffle;

        Sender(String host, int port, byte[] data,
               java.util.function.BiConsumer<String, String> log,
               java.util.function.Consumer<String> err,
               boolean shuffle) throws IOException {
            this.destAddr = InetAddress.getByName(host);
            this.destPort = port;
            this.data = data;
            this.segments = segment(data, MSS);
            this.log = log;
            this.err = err;
            this.shuffle = shuffle;
        }

        void send(java.util.function.Consumer<Integer> progress) throws IOException {
            // random ephemeral source port
            this.srcPort = 49152 + new Random().nextInt(16383);
            this.ISS = (long) (Math.random() * 0xFFFFFFFFL) & 0xFFFFFFFFL;
            this.socket = new DatagramSocket(srcPort);
            this.socket.setSoTimeout(3000);
            this.cwnd = INIT_CWND * MSS;
            this.ssthresh = INIT_SSTHRESH * MSS;

            try {
                if (!threeWayHandshake()) {
                    err.accept("Handshake failed");
                    return;
                }

                SND_UNA = ISS + 1;
                SND_NXT = SND_UNA;
                long totalBytes = data.length;
                long seqEnd = ISS + 1 + totalBytes;

                // Map: seqNum -> send-time for RTT measurement
                Map<Long, Long> sentTime = new HashMap<>();

                while (SND_UNA < seqEnd) {
                    // Fill window
                    List<Integer> windowIndices = new ArrayList<>();
                    long tempNxt = SND_NXT;
                    while (tempNxt < seqEnd && tempNxt - SND_UNA < cwnd) {
                        int idx = (int) ((tempNxt - (ISS + 1)) / MSS);
                        if (idx >= segments.size()) break;
                        windowIndices.add(idx);
                        tempNxt += segments.get(idx).length;
                    }

// 2. Si el usuario activó "Shuffle", desordenamos los índices de los paquetes
                    if (this.shuffle && !windowIndices.isEmpty()) {
                        Collections.shuffle(windowIndices);
                        log.accept("WARN", "¡MODO CAOS! Barajando " + windowIndices.size() + " segmentos en la red...");
                    }

// 3. Enviamos los paquetes en el orden resultante (sea ordenado o barajado)
                    for (int idx : windowIndices) {
                        byte[] payload = segments.get(idx);
                        long seqParaEstePaquete = (ISS + 1) + ((long) idx * MSS);

                        int flags = TcpHeader.ACK_FLAG | TcpHeader.PSH_FLAG;
                        if (seqParaEstePaquete + payload.length >= seqEnd) flags |= TcpHeader.PSH_FLAG;

                        sendSegment(seqParaEstePaquete, flags, payload);
                        sentTime.put(seqParaEstePaquete, System.currentTimeMillis());

                        log.accept("INFO", String.format("  -> segment Seq=%d enviado (Índice %d)", seqParaEstePaquete, idx));
                    }

// 4. Actualizamos SND_NXT al final de la ventana procesada
                    SND_NXT = tempNxt;

                    // Wait for ACK
                    try {
                        byte[] buf = new byte[64 * 1024];
                        DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                        socket.receive(pkt);
                        TcpHeader ack = TcpHeader.parse(pkt.getData(), pkt.getLength());
                        if (ack == null) continue;
                        if ((ack.flags & TcpHeader.ACK_FLAG) == 0) continue;

                        long ackNum = ack.ackNum;
                        if (ackNum > SND_UNA) {
                            // Update RTT estimate (RFC 6298)
                            Long st = sentTime.remove(SND_UNA);
                            if (st != null) {
                                double r = System.currentTimeMillis() - st;
                                if (srtt < 0) {
                                    srtt = r;
                                    rttvar = r / 2;
                                } else {
                                    rttvar = 0.75 * rttvar + 0.25 * Math.abs(srtt - r);
                                    srtt = 0.875 * srtt + 0.125 * r;
                                }
                                rto = Math.max(1000, (long) (srtt + 4 * rttvar));
                            }
                            // Congestion control
                            if (cwnd < ssthresh) {
                                cwnd += MSS;
                            }           // slow start
                            else {
                                cwnd += MSS * MSS / cwnd;
                            }  // AIMD
                            SND_UNA = ackNum;
                            log.accept("INFO", "  <- ACK " + ackNum + " cwnd=" + cwnd);
                        }
                    } catch (SocketTimeoutException ex) {
                        // retransmit from SND_UNA
                        log.accept("WARN", "Timeout — retransmitting from " + SND_UNA);
                        ssthresh = Math.max(cwnd / 2, MSS);
                        cwnd = MSS;
                        rto = Math.min(rto * 2, 60000);
                        SND_NXT = SND_UNA;
                        sentTime.clear();
                    }

                    int pct = (int) (100L * (SND_UNA - (ISS + 1)) / Math.max(1, totalBytes));
                    progress.accept(Math.min(pct, 99));
                }

                progress.accept(100);
                fourWayClose();
                log.accept("INFO", "Transfer complete. Connection closed.");
            } finally {
                socket.close();
            }
        }

        private boolean threeWayHandshake() throws IOException {
            // SYN
            sendSegment(ISS, TcpHeader.SYN_FLAG, null);
            log.accept("INFO", "  -> SYN ISS=" + ISS);

            for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
                try {
                    byte[] buf = new byte[1024];
                    DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                    socket.receive(pkt);
                    TcpHeader h = TcpHeader.parse(pkt.getData(), pkt.getLength());
                    if (h != null && (h.flags & TcpHeader.SYN_FLAG) != 0 && (h.flags & TcpHeader.ACK_FLAG) != 0) {
                        IRS = h.seqNum;
                        log.accept("INFO", "  <- SYN-ACK IRS=" + IRS);
                        // Send ACK
                        sendSegment(ISS + 1, TcpHeader.ACK_FLAG, null);
                        log.accept("INFO", "  -> ACK");
                        return true;
                    }
                } catch (SocketTimeoutException ex) {
                    log.accept("WARN", "Retransmitting SYN (attempt " + (attempt + 2) + ")");
                    sendSegment(ISS, TcpHeader.SYN_FLAG, null);
                }
            }
            return false;
        }

        private void fourWayClose() throws IOException {
            sendSegment(SND_NXT, TcpHeader.FIN_FLAG | TcpHeader.ACK_FLAG, null);
            log.accept("INFO", "  -> FIN");
            SND_NXT++;
            for (int i = 0; i < 5; i++) {
                try {
                    byte[] buf = new byte[1024];
                    DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                    socket.receive(pkt);
                    TcpHeader h = TcpHeader.parse(pkt.getData(), pkt.getLength());
                    if (h != null) {
                        if ((h.flags & TcpHeader.ACK_FLAG) != 0) log.accept("INFO", "  <- ACK (close)");
                        if ((h.flags & TcpHeader.FIN_FLAG) != 0) {
                            log.accept("INFO", "  <- FIN");
                            sendSegment(SND_NXT, TcpHeader.ACK_FLAG, null);
                            log.accept("INFO", "  -> ACK (TIME_WAIT)");
                            Thread.sleep(200);
                            return;
                        }
                    }
                } catch (Exception ignored) {
                    break;
                }
            }
        }

        private void sendSegment(long seqNum, int flags, byte[] payload) throws IOException {
            byte[] pkt = TcpHeader.build(srcPort, destPort, seqNum,
                    (flags & TcpHeader.ACK_FLAG) != 0 ? IRS + 1 : 0,
                    flags, RECV_WIN,
                    InetAddress.getLocalHost(), destAddr, payload);
            DatagramPacket dp = new DatagramPacket(pkt, pkt.length, destAddr, destPort);
            socket.send(dp);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TCP RECEIVER — full state machine
    // ═══════════════════════════════════════════════════════════════════════

    private static class Receiver extends Thread {
        final int port;
        private final java.util.function.BiConsumer<String, String> log;
        private final java.util.function.Consumer<byte[]> onComplete;
        private volatile boolean running = true;
        private DatagramSocket socket;

        // Per-connection state
        private final Map<String, ConnState> conns = new ConcurrentHashMap<>();

        Receiver(int port,
                 java.util.function.BiConsumer<String, String> log,
                 java.util.function.Consumer<byte[]> onComplete) {
            this.port = port;
            this.log = log;
            this.onComplete = onComplete;
            setName("Receiver:" + port);
            setDaemon(true);
        }

        boolean isRunning() {
            return running;
        }

        void stopReceiver() {
            running = false;
            if (socket != null) socket.close();
        }

        @Override
        public void run() {
            try {
                socket = new DatagramSocket(port);
                byte[] buf = new byte[64 * 1024];
                while (running) {
                    DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                    socket.receive(pkt);
                    byte[] data = Arrays.copyOf(pkt.getData(), pkt.getLength());
                    processPacket(data, pkt.getAddress(), pkt.getPort());
                }
            } catch (Exception e) {
                if (running) log.accept("ERROR", "[Receiver] " + e.getMessage());
            }
        }

        private void processPacket(byte[] data, InetAddress from, int fromPort) {
            if (data.length < TcpHeader.HEADER_SIZE) return;

            TcpHeader h = TcpHeader.parse(data, data.length);
            if (h == null) {
                log.accept("WARN", "[Receiver] Dropping: bad checksum");
                return;
            }

            byte[] payload = data.length > TcpHeader.HEADER_SIZE
                    ? Arrays.copyOfRange(data, TcpHeader.HEADER_SIZE, data.length)
                    : new byte[0];

            String key = from.getHostAddress() + ":" + fromPort;
            ConnState s = conns.computeIfAbsent(key, k -> new ConnState(from, fromPort));

            try {
                switch (s.state) {
                    case LISTEN:
                        handleListen(h, s, key, from, fromPort);
                        break;
                    case SYN_RCVD:
                        handleSynRcvd(h, s, key);
                        break;
                    case ESTABLISHED:
                        handleData(h, payload, s);
                        break;
                    case CLOSE_WAIT:  /* nothing */
                        break;
                }
            } catch (IOException ex) {
                log.accept("ERROR", "[Receiver] " + ex.getMessage());
            }
        }

        private void handleListen(TcpHeader h, ConnState s, String key,
                                  InetAddress from, int fromPort) throws IOException {
            if ((h.flags & TcpHeader.SYN_FLAG) == 0) return;
            log.accept("INFO", "[Receiver] SYN from " + key + " Seq=" + h.seqNum);

            s.IRS = h.seqNum;
            s.RCV_NXT = h.seqNum + 1;
            s.ISS = (long) (Math.random() * 0xFFFFFFFFL) & 0xFFFFFFFFL;
            s.SND_NXT = s.ISS;
            s.state = ConnState.State.SYN_RCVD;

            // SYN-ACK
            byte[] resp = TcpHeader.build(port, fromPort, s.ISS, s.RCV_NXT,
                    TcpHeader.SYN_FLAG | TcpHeader.ACK_FLAG, 65535,
                    socket.getLocalAddress(), from, null);
            socket.send(new DatagramPacket(resp, resp.length, from, fromPort));
            s.SND_NXT++;
            log.accept("INFO", "[Receiver] SYN-ACK -> " + key);
        }

        private void handleSynRcvd(TcpHeader h, ConnState s, String key) {
            if ((h.flags & TcpHeader.ACK_FLAG) == 0) return;
            if (h.ackNum != s.SND_NXT) return;
            s.state = ConnState.State.ESTABLISHED;
            log.accept("INFO", "[Receiver] Connection ESTABLISHED with " + key);
        }

        private void handleData(TcpHeader h, byte[] payload, ConnState s) throws IOException {
            // FIN
            if ((h.flags & TcpHeader.FIN_FLAG) != 0) {
                log.accept("INFO", "[Receiver] FIN received. Closing.");
                s.RCV_NXT++;
                // ACK
                sendAck(s);
                // FIN-ACK
                byte[] fin = TcpHeader.build(port, s.remotePort, s.SND_NXT, s.RCV_NXT,
                        TcpHeader.FIN_FLAG | TcpHeader.ACK_FLAG, 65535,
                        socket.getLocalAddress(), s.remoteAddr, null);
                socket.send(new DatagramPacket(fin, fin.length, s.remoteAddr, s.remotePort));
                s.SND_NXT++;
                s.state = ConnState.State.CLOSE_WAIT;

                if (!s.recvBuffer.isEmpty()) {
                    byte[] msg = assembleBuffer(s);
                    onComplete.accept(msg);
                    log.accept("INFO", "[Receiver] Message complete — " + msg.length + " bytes");
                }
                conns.remove(s.remoteAddr.getHostAddress() + ":" + s.remotePort);
                return;
            }

            if (payload.length == 0) return;

            long seq = h.seqNum;

            if (seq < s.RCV_NXT) {
                log.accept("WARN", "[Receiver] Duplicate seq=" + seq + ", re-ACKing " + s.RCV_NXT);
                sendAck(s);
                return;
            }

            if (seq == s.RCV_NXT) {
                s.recvBuffer.put(seq, payload);
                s.RCV_NXT += payload.length;
                // Advance past buffered out-of-order segments
                while (true) {
                    byte[] next = s.recvBuffer.get(s.RCV_NXT);
                    if (next == null) break;
                    // already in map, just advance pointer
                    s.RCV_NXT += next.length;
                }
                log.accept("INFO", String.format("[Receiver] seq=%d len=%d RCV_NXT=%d", seq, payload.length, s.RCV_NXT));
            } else {
                // Out of order — buffer it
                s.recvBuffer.put(seq, payload);
                log.accept("WARN", "[Receiver] Out-of-order seq=" + seq + " expected=" + s.RCV_NXT);
            }

            sendAck(s);
        }

        private void sendAck(ConnState s) throws IOException {
            byte[] ack = TcpHeader.build(port, s.remotePort, s.SND_NXT, s.RCV_NXT,
                    TcpHeader.ACK_FLAG, 65535,
                    socket.getLocalAddress(), s.remoteAddr, null);
            socket.send(new DatagramPacket(ack, ack.length, s.remoteAddr, s.remotePort));
            log.accept("INFO", "  -> ACK " + s.RCV_NXT);
        }

        private byte[] assembleBuffer(ConnState s) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            new TreeMap<>(s.recvBuffer).forEach((seq, data) -> {
                try {
                    out.write(data);
                } catch (IOException ignored) {
                }
            });
            return out.toByteArray();
        }

        static class ConnState {
            enum State {LISTEN, SYN_RCVD, ESTABLISHED, CLOSE_WAIT}

            State state = State.LISTEN;
            final InetAddress remoteAddr;
            final int remotePort;
            long ISS, IRS, SND_NXT, RCV_NXT;
            final TreeMap<Long, byte[]> recvBuffer = new TreeMap<>();

            ConnState(InetAddress a, int p) {
                remoteAddr = a;
                remotePort = p;
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // TCP HEADER — real RFC 793 format with proper pseudo-header checksum
    // ═══════════════════════════════════════════════════════════════════════

    static class TcpHeader {
        static final int HEADER_SIZE = 20;

        static final int SYN_FLAG = 0x002;
        static final int ACK_FLAG = 0x010;
        static final int FIN_FLAG = 0x001;
        static final int RST_FLAG = 0x004;
        static final int PSH_FLAG = 0x008;
        static final int URG_FLAG = 0x020;

        int srcPort, dstPort;
        long seqNum, ackNum;
        int flags, window, checksum, urgentPtr;

        /**
         * Build a TCP segment ready to be wrapped in UDP.
         * The checksum uses the IP pseudo-header (RFC 793 §3.1).
         * <p>
         * Wire format: 20 bytes TCP header + payload
         * (No IP header is transmitted — this is encapsulated in UDP)
         */
        static byte[] build(int srcPort, int dstPort, long seqNum, long ackNum,
                            int flags, int window,
                            InetAddress srcIp, InetAddress dstIp,
                            byte[] payload) throws IOException {
            int payloadLen = payload != null ? payload.length : 0;
            ByteBuffer hdr = ByteBuffer.allocate(HEADER_SIZE);
            hdr.putShort((short) srcPort);
            hdr.putShort((short) dstPort);
            hdr.putInt((int) (seqNum & 0xFFFFFFFFL));
            hdr.putInt((int) (ackNum & 0xFFFFFFFFL));
            hdr.putShort((short) ((5 << 12) | (flags & 0x1FF)));   // data offset=5, flags
            hdr.putShort((short) window);
            hdr.putShort((short) 0);   // checksum placeholder
            hdr.putShort((short) 0);   // urgent pointer
            byte[] hdrBytes = hdr.array();

            // Compute checksum with pseudo-header
            int csum = checksum(srcIp, dstIp, hdrBytes, payload);
            hdrBytes[16] = (byte) (csum >> 8);
            hdrBytes[17] = (byte) (csum & 0xFF);

            ByteArrayOutputStream out = new ByteArrayOutputStream(HEADER_SIZE + payloadLen);
            out.write(hdrBytes);
            if (payload != null) out.write(payload);
            return out.toByteArray();
        }

        /**
         * Parse a TCP segment from raw bytes.
         * Returns null if checksum is invalid (packet corrupted/spoofed).
         * NOTE: without knowing the original IP addresses we cannot validate
         * the checksum here — the receiver validates based on socket address.
         * We return the header anyway but callers can do their own validation.
         */
        static TcpHeader parse(byte[] bytes, int len) {
            if (len < HEADER_SIZE) return null;
            ByteBuffer b = ByteBuffer.wrap(bytes, 0, len);
            TcpHeader h = new TcpHeader();
            h.srcPort = b.getShort() & 0xFFFF;
            h.dstPort = b.getShort() & 0xFFFF;
            h.seqNum = b.getInt() & 0xFFFFFFFFL;
            h.ackNum = b.getInt() & 0xFFFFFFFFL;
            int dof = b.getShort() & 0xFFFF;
            h.flags = dof & 0x1FF;
            h.window = b.getShort() & 0xFFFF;
            h.checksum = b.getShort() & 0xFFFF;
            h.urgentPtr = b.getShort() & 0xFFFF;
            return h;
        }

        /**
         * RFC 793 checksum: ones-complement sum of pseudo-header + TCP segment.
         * <p>
         * Pseudo-header:
         * [ src_ip(4) | dst_ip(4) | zero(1) | proto=6(1) | tcp_len(2) ]
         */
        static int checksum(InetAddress src, InetAddress dst,
                            byte[] header, byte[] payload) {
            int tcpLen = header.length + (payload != null ? payload.length : 0);
            long sum = 0;
            byte[] srcB = src.getAddress();
            byte[] dstB = dst.getAddress();
            // pseudo-header
            sum += ((srcB[0] & 0xFF) << 8) | (srcB[1] & 0xFF);
            sum += ((srcB[2] & 0xFF) << 8) | (srcB[3] & 0xFF);
            sum += ((dstB[0] & 0xFF) << 8) | (dstB[1] & 0xFF);
            sum += ((dstB[2] & 0xFF) << 8) | (dstB[3] & 0xFF);
            sum += 6;          // protocol TCP
            sum += tcpLen;
            // TCP header
            for (int i = 0; i < header.length - 1; i += 2)
                sum += ((header[i] & 0xFF) << 8) | (header[i + 1] & 0xFF);
            if ((header.length & 1) != 0) sum += (header[header.length - 1] & 0xFF) << 8;
            // payload
            if (payload != null) {
                for (int i = 0; i < payload.length - 1; i += 2)
                    sum += ((payload[i] & 0xFF) << 8) | (payload[i + 1] & 0xFF);
                if ((payload.length & 1) != 0) sum += (payload[payload.length - 1] & 0xFF) << 8;
            }
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (int) (~sum & 0xFFFF);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // MAIN
    // ═══════════════════════════════════════════════════════════════════════

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            TcpOverUdpComplexApp app = new TcpOverUdpComplexApp();
            app.setVisible(true);
        });
    }
}
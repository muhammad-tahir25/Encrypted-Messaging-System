# =============================================================
# Encrypted Chat — PyQt5 GUI
# Dark terminal-style UI with live AES vs ECC timing panel
# =============================================================

import sys
import os
import threading
import queue

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QScrollArea, QFrame,
    QSizePolicy, QDialog, QGraphicsDropShadowEffect
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve, QRect
from PyQt5.QtGui import QFont, QColor, QPalette, QFontDatabase, QPainter, QLinearGradient

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from client.client import ChatClient


# ─────────────────────────────────────────────
# COLOUR PALETTE
# ─────────────────────────────────────────────

BG_DARK    = "#0a0e1a"
BG_MID     = "#0f1628"
BG_PANEL   = "#111827"
BG_INPUT   = "#1a2035"
ACCENT     = "#00d4ff"
ACCENT2    = "#7c3aed"
GREEN      = "#10b981"
ORANGE     = "#f59e0b"
RED_COL    = "#ef4444"
TEXT_MAIN  = "#e2e8f0"
TEXT_DIM   = "#64748b"
BORDER     = "#1e2d45"
BUBBLE_OUT = "#1a3a5c"
BUBBLE_IN  = "#1a1f35"
SYSTEM_COL = "#334155"


# ─────────────────────────────────────────────
# LOGIN DIALOG
# ─────────────────────────────────────────────

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.username = ""
        self.setWindowTitle("Encrypted Chat — Connect")
        self.setFixedSize(600, 460)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {BG_DARK};
                border: 1px solid {BORDER};
            }}
        """)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)

        # Title
        title = QLabel("⬡ ENCRYPTED CHAT")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 34px;
            font-weight: 800;
            letter-spacing: 4px;
            font-family: 'Courier New', monospace;
        """)
        layout.addWidget(title)

        subtitle = QLabel("AES-256  ·  ECC secp256k1  ·  End-to-End")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(f"color: {TEXT_DIM}; font-size: 15px; letter-spacing: 2px;")
        layout.addWidget(subtitle)

        layout.addSpacing(10)

        # Username field
        lbl = QLabel("USERNAME")
        lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 10px; letter-spacing: 2px;")
        layout.addWidget(lbl)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your name...")
        self.username_input.setStyleSheet(f"""
            QLineEdit {{
                background: {BG_INPUT};
                border: 1px solid {BORDER};
                border-radius: 6px;
                color: {TEXT_MAIN};
                padding: 14px 18px;
                font-size: 18px;
                font-family: 'Courier New', monospace;
            }}
            QLineEdit:focus {{
                border: 1px solid {ACCENT};
            }}
        """)
        self.username_input.returnPressed.connect(self._connect)
        layout.addWidget(self.username_input)

        # Status label
        self.status_lbl = QLabel("")
        self.status_lbl.setAlignment(Qt.AlignCenter)
        self.status_lbl.setStyleSheet(f"color: {RED_COL}; font-size: 11px;")
        layout.addWidget(self.status_lbl)

        # Connect button
        btn = QPushButton("CONNECT  →")
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {ACCENT}, stop:1 {ACCENT2});
                color: white;
                border: none;
                border-radius: 6px;
                padding: 16px;
                font-size: 17px;
                font-weight: 700;
                letter-spacing: 2px;
            }}
            QPushButton:hover {{ opacity: 0.9; }}
            QPushButton:pressed {{ opacity: 0.7; }}
        """)
        btn.clicked.connect(self._connect)
        layout.addWidget(btn)

    def _connect(self):
        name = self.username_input.text().strip()
        if not name:
            self.status_lbl.setText("Username already exist please enter another username.")
            return
        if len(name) > 20:
            self.status_lbl.setText("Name too long (max 20 chars).")
            return

        self.username = name
        self.accept()


# ─────────────────────────────────────────────
# TIMING BAR WIDGET
# ─────────────────────────────────────────────

class TimingBar(QWidget):
    """Animated bar showing ms value for one algorithm"""
    def __init__(self, label: str, color: str):
        super().__init__()
        self.color = color
        self.setFixedHeight(54)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.label = QLabel(label)
        self.label.setFixedWidth(100)
        self.label.setStyleSheet(f"color: {TEXT_DIM}; font-size: 16px; font-weight: 700; letter-spacing: 1px;")
        layout.addWidget(self.label)

        bar_container = QWidget()
        bar_container.setFixedHeight(6)
        bar_layout = QHBoxLayout(bar_container)
        bar_layout.setContentsMargins(0, 0, 0, 0)

        self.bar = QLabel()
        self.bar.setFixedHeight(6)
        self.bar.setStyleSheet(f"background: {color}; border-radius: 3px;")
        bar_layout.addWidget(self.bar)
        bar_layout.addStretch()

        right = QVBoxLayout()
        right.setSpacing(2)
        right.addWidget(bar_container)

        self.time_lbl = QLabel("— ms")
        self.time_lbl.setStyleSheet(f"color: {color}; font-size: 15px; font-family: 'Courier New'; font-weight: 700;")
        right.addWidget(self.time_lbl)

        layout.addLayout(right)

    def update_value(self, enc_ms: float, dec_ms: float, max_ms: float = 200.0):
        total = enc_ms + dec_ms
        self.time_lbl.setText(f"enc {enc_ms:.2f}ms  |  dec {dec_ms:.2f}ms")
        ratio = min(total / max_ms, 1.0)
        bar_width = max(4, int(ratio * 180))
        self.bar.setFixedWidth(bar_width)


# ─────────────────────────────────────────────
# TIMING PANEL
# ─────────────────────────────────────────────

class TimingPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(f"""
            QFrame {{
                background: {BG_PANEL};
                border: 1px solid {BORDER};
                border-radius: 10px;
            }}
        """)
        self.setFixedWidth(360)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header
        hdr = QLabel("⚡ CRYPTO TIMING")
        hdr.setStyleSheet(f"color: {ACCENT}; font-size: 15px; font-weight: 700; letter-spacing: 2px;")
        layout.addWidget(hdr)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color: {BORDER};")
        layout.addWidget(sep)

        # Bars
        self.aes_bar = TimingBar("AES-256", GREEN)
        self.ecc_bar = TimingBar("ECC", ORANGE)
        layout.addWidget(self.aes_bar)
        layout.addWidget(self.ecc_bar)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.HLine)
        sep2.setStyleSheet(f"color: {BORDER};")
        layout.addWidget(sep2)

        # Winner label
        self.winner_lbl = QLabel("Send a message to\nsee comparison")
        self.winner_lbl.setAlignment(Qt.AlignCenter)
        self.winner_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 16px;")
        layout.addWidget(self.winner_lbl)

        # Stats
        self.msg_count_lbl = QLabel("Messages: 0")
        self.msg_count_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 15px;")
        layout.addWidget(self.msg_count_lbl)

        self.avg_aes_lbl = QLabel("Avg AES: —")
        self.avg_aes_lbl.setStyleSheet(f"color: {GREEN}; font-size: 15px; font-family: 'Courier New';")
        layout.addWidget(self.avg_aes_lbl)

        self.avg_ecc_lbl = QLabel("Avg ECC: —")
        self.avg_ecc_lbl.setStyleSheet(f"color: {ORANGE}; font-size: 15px; font-family: 'Courier New';")
        layout.addWidget(self.avg_ecc_lbl)

        layout.addStretch()

        self._aes_times = []
        self._ecc_times = []
        self._msg_count = 0

    def update_timing(self, timing: dict):
        aes_total = timing['aes_enc'] + timing['aes_dec']
        ecc_total = timing['ecc_enc'] + timing['ecc_dec']

        self.aes_bar.update_value(timing['aes_enc'], timing['aes_dec'])
        self.ecc_bar.update_value(timing['ecc_enc'], timing['ecc_dec'])

        self._aes_times.append(aes_total)
        self._ecc_times.append(ecc_total)
        self._msg_count += 1

        # Winner
        if aes_total < ecc_total:
            diff = ecc_total - aes_total
            self.winner_lbl.setText(
                f"🏆 AES faster\nby {diff:.2f} ms this msg"
            )
            self.winner_lbl.setStyleSheet(f"color: {GREEN}; font-size: 14px; font-weight: 700;")
        else:
            diff = aes_total - ecc_total
            self.winner_lbl.setText(
                f"🏆 ECC faster\nby {diff:.2f} ms this msg"
            )
            self.winner_lbl.setStyleSheet(f"color: {ORANGE}; font-size: 14px; font-weight: 700;")

        # Averages
        self.msg_count_lbl.setText(f"Messages: {self._msg_count}")
        avg_aes = sum(self._aes_times) / len(self._aes_times)
        avg_ecc = sum(self._ecc_times) / len(self._ecc_times)
        self.avg_aes_lbl.setText(f"Avg AES: {avg_aes:.2f} ms")
        self.avg_ecc_lbl.setText(f"Avg ECC: {avg_ecc:.2f} ms")


# ─────────────────────────────────────────────
# MESSAGE BUBBLE
# ─────────────────────────────────────────────

class MessageBubble(QFrame):
    def __init__(self, sender: str, text: str, timing: dict = None,
                 is_self: bool = False, is_system: bool = False):
        super().__init__()
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(8, 4, 8, 4)

        bubble = QFrame()
        bubble.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Minimum)

        if is_system:
            bubble.setStyleSheet(f"""
                background: {SYSTEM_COL};
                border-radius: 8px;
                padding: 2px;
            """)
            bubble_layout = QVBoxLayout(bubble)
            bubble_layout.setContentsMargins(14, 10, 14, 10)
            lbl = QLabel(f"⚙  {text}")
            lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 13px; font-style: italic;")
            lbl.setWordWrap(True)
            bubble_layout.addWidget(lbl)
            outer.addStretch()
            outer.addWidget(bubble)
            outer.addStretch()
            return

        bg = BUBBLE_OUT if is_self else BUBBLE_IN
        border_col = ACCENT if is_self else ACCENT2

        if is_self:
            bubble.setStyleSheet(f"""
                background: {bg};
                border: 1px solid {border_col}40;
                border-radius: 12px;
                border-bottom-right-radius: 2px;
            """)
        else:
            bubble.setStyleSheet(f"""
                background: {bg};
                border: 1px solid {border_col}40;
                border-radius: 12px;
                border-bottom-left-radius: 2px;
            """)
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(14, 10, 14, 10)
        bubble_layout.setSpacing(4)

        # Sender name
        if not is_self:
            name_lbl = QLabel(sender)
            name_lbl.setStyleSheet(f"color: {ACCENT2}; font-size: 15px; font-weight: 700; letter-spacing: 1px;")
            name_lbl.setMinimumWidth(200)
            bubble_layout.addWidget(name_lbl)

        # Message text
        msg_lbl = QLabel()
        msg_lbl.setText(text if text else "(empty)")
        msg_lbl.setStyleSheet(f"color: {TEXT_MAIN}; font-size: 17px; padding: 2px;")
        msg_lbl.setWordWrap(True)
        msg_lbl.setMinimumWidth(200)
        msg_lbl.setMinimumHeight(24)
        msg_lbl.setMaximumWidth(600)
        msg_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        msg_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        bubble_layout.addWidget(msg_lbl)

        # Timing info — two separate lines for clarity
        if timing:
            aes_lbl = QLabel(
                f"🔒 AES   enc {timing['aes_enc']:.2f}ms  ·  dec {timing['aes_dec']:.2f}ms"
            )
            aes_lbl.setStyleSheet(f"color: {GREEN}; font-size: 13px; font-family: 'Courier New';")
            aes_lbl.setMinimumWidth(200)
            bubble_layout.addWidget(aes_lbl)

            ecc_lbl = QLabel(
                f"🔑 ECC   enc {timing['ecc_enc']:.2f}ms  ·  dec {timing['ecc_dec']:.2f}ms"
            )
            ecc_lbl.setStyleSheet(f"color: {ORANGE}; font-size: 13px; font-family: 'Courier New';")
            ecc_lbl.setMinimumWidth(200)
            bubble_layout.addWidget(ecc_lbl)

        if is_self:
            outer.addStretch()
            outer.addWidget(bubble)
        else:
            outer.addWidget(bubble)
            outer.addStretch()


# ─────────────────────────────────────────────
# USERS PANEL
# ─────────────────────────────────────────────

class UsersPanel(QFrame):
    def __init__(self):
        super().__init__()
        self.setFixedWidth(220)
        self.setStyleSheet(f"""
            QFrame {{
                background: {BG_PANEL};
                border: 1px solid {BORDER};
                border-radius: 10px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 18, 16, 18)
        layout.setSpacing(12)

        hdr = QLabel("ONLINE")
        hdr.setStyleSheet(f"color: {GREEN}; font-size: 15px; font-weight: 700; letter-spacing: 2px;")
        layout.addWidget(hdr)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color: {BORDER};")
        layout.addWidget(sep)

        self.users_layout = QVBoxLayout()
        self.users_layout.setSpacing(6)
        layout.addLayout(self.users_layout)
        layout.addStretch()

    def update_users(self, users: list):
        # Properly clear all items including nested layouts
        def clear_layout(layout):
            while layout.count():
                item = layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
                elif item.layout():
                    clear_layout(item.layout())

        clear_layout(self.users_layout)

        # Rebuild with deduplicated users
        seen = set()
        for u in users:
            if u in seen:
                continue
            seen.add(u)
            row = QHBoxLayout()
            dot = QLabel("●")
            dot.setStyleSheet(f"color: {GREEN}; font-size: 10px;")
            name = QLabel(u)
            name.setStyleSheet(f"color: {TEXT_MAIN}; font-size: 16px;")
            row.addWidget(dot)
            row.addWidget(name)
            row.addStretch()
            self.users_layout.addLayout(row)


# ─────────────────────────────────────────────
# MAIN CHAT WINDOW
# ─────────────────────────────────────────────

class ChatWindow(QMainWindow):
    # Use a simple signal with no text — text is passed via thread-safe queue
    sig_message    = pyqtSignal()
    sig_system     = pyqtSignal(str)
    sig_user_list  = pyqtSignal(list)
    sig_connected  = pyqtSignal()
    sig_disconnected = pyqtSignal()
    sig_error      = pyqtSignal(str)

    def __init__(self, username: str):
        super().__init__()
        self.username = username
        self._username_taken = False
        self._msg_queue = queue.Queue()  # Thread-safe message queue
        self.client = ChatClient(username)
        self._setup_client_callbacks()
        self._build_ui()
        self._connect_signals()
        self.client.connect()

    # ─────────────────────────────────────────
    # CLIENT CALLBACKS  (called from thread)
    # ─────────────────────────────────────────

    def _setup_client_callbacks(self):
        def on_message(sender, plaintext, timing):
            # Put message data in thread-safe queue
            self._msg_queue.put({
                'sender': sender,
                'text': plaintext,
                'timing': timing
            })
            # Signal the UI thread to process the queue
            self.sig_message.emit()

        def on_system(msg):
            self.sig_system.emit(msg)

        def on_user_list(users):
            self.sig_user_list.emit(users)

        def on_connected():
            self.sig_connected.emit()

        def on_disconnected():
            self.sig_disconnected.emit()

        def on_error(err):
            self.sig_error.emit(err)

        self.client.on_message      = on_message
        self.client.on_system       = on_system
        self.client.on_user_list    = on_user_list
        self.client.on_connected    = on_connected
        self.client.on_disconnected = on_disconnected
        self.client.on_error        = on_error

    # ─────────────────────────────────────────
    # SIGNAL → SLOT (runs on main/UI thread)
    # ─────────────────────────────────────────

    def _connect_signals(self):
        self.sig_message.connect(self._on_message)
        self.sig_system.connect(self._on_system)
        self.sig_user_list.connect(self._on_user_list)
        self.sig_connected.connect(self._on_connected)
        self.sig_disconnected.connect(self._on_disconnected)
        self.sig_error.connect(self._on_error)

    def _on_message(self):
        # Process all pending messages from queue
        while not self._msg_queue.empty():
            msg = self._msg_queue.get()
            sender  = msg['sender']
            text    = msg['text']
            timing  = msg['timing']
            print(f"[GUI] Message from {sender}: '{text}'")
            self._add_bubble(sender, text, timing, is_self=False)
            self.timing_panel.update_timing(timing)

    def _on_system(self, msg):
        self._add_bubble("", msg, None, is_system=True)

    def _on_user_list(self, users):
        self.users_panel.update_users(users)

    def _on_connected(self):
        self.status_dot.setStyleSheet(f"color: {GREEN}; font-size: 15px;")
        self.status_lbl.setText("CONNECTED")
        self.status_lbl.setStyleSheet(f"color: {GREEN}; font-size: 15px; letter-spacing: 1px;")
        self.input_field.setEnabled(True)
        self.send_btn.setEnabled(True)

    def _on_disconnected(self):
        self.status_dot.setStyleSheet(f"color: {RED_COL}; font-size: 15px;")
        self.status_lbl.setText("DISCONNECTED")
        self.status_lbl.setStyleSheet(f"color: {RED_COL}; font-size: 15px; letter-spacing: 1px;")
        self.input_field.setEnabled(False)
        self.send_btn.setEnabled(False)

    def _on_error(self, err):
        if 'already taken' in err:
            from PyQt5.QtWidgets import QMessageBox
            self._username_taken = True
            msg = QMessageBox()
            msg.setWindowTitle("Username Taken")
            msg.setText(err)
            msg.setIcon(QMessageBox.Warning)
            msg.setStyleSheet(f"background-color: {BG_DARK}; color: {TEXT_MAIN};")
            msg.exec_()
            self.client.disconnect()
            self.close()
        else:
            self._add_bubble("", f"Error: {err}", None, is_system=True)

    # ─────────────────────────────────────────
    # BUILD UI
    # ─────────────────────────────────────────

    def _build_ui(self):
        self.setWindowTitle(f"Encrypted Chat — {self.username}")
        self.setMinimumSize(1100, 700)
        self.resize(1280, 820)
        self.setStyleSheet(f"background-color: {BG_DARK};")

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Top bar ──
        topbar = QFrame()
        topbar.setFixedHeight(72)
        topbar.setStyleSheet(f"""
            background: {BG_MID};
            border-bottom: 1px solid {BORDER};
        """)
        tb_layout = QHBoxLayout(topbar)
        tb_layout.setContentsMargins(28, 0, 28, 0)

        logo = QLabel("⬡ ENCRYPTED CHAT")
        logo.setStyleSheet(f"""
            color: {ACCENT};
            font-size: 24px;
            font-weight: 800;
            letter-spacing: 3px;
            font-family: 'Courier New', monospace;
        """)
        tb_layout.addWidget(logo)
        tb_layout.addStretch()

        self.status_dot = QLabel("●")
        self.status_dot.setStyleSheet(f"color: {ORANGE}; font-size: 15px;")
        self.status_lbl = QLabel("CONNECTING...")
        self.status_lbl.setStyleSheet(f"color: {ORANGE}; font-size: 15px; letter-spacing: 1px;")

        user_lbl = QLabel(f"  {self.username}")
        user_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 16px;")

        tb_layout.addWidget(self.status_dot)
        tb_layout.addWidget(self.status_lbl)
        tb_layout.addWidget(user_lbl)

        root.addWidget(topbar)

        # ── Main body ──
        body = QHBoxLayout()
        body.setContentsMargins(12, 12, 12, 12)
        body.setSpacing(12)

        # Left: users panel
        self.users_panel = UsersPanel()
        body.addWidget(self.users_panel)

        # Center: chat area
        chat_col = QVBoxLayout()
        chat_col.setSpacing(8)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet(f"""
            QScrollArea {{
                background: {BG_MID};
                border: 1px solid {BORDER};
                border-radius: 10px;
            }}
            QScrollBar:vertical {{
                background: {BG_DARK};
                width: 6px;
                border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: {BORDER};
                border-radius: 3px;
            }}
        """)

        self.messages_widget = QWidget()
        self.messages_widget.setStyleSheet(f"background: {BG_MID};")
        self.messages_layout = QVBoxLayout(self.messages_widget)
        self.messages_layout.setContentsMargins(8, 12, 8, 12)
        self.messages_layout.setSpacing(4)
        self.messages_layout.addStretch()

        self.scroll_area.setWidget(self.messages_widget)
        chat_col.addWidget(self.scroll_area)

        # Input row
        input_row = QHBoxLayout()
        input_row.setSpacing(10)

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Type a message and press Enter...")
        self.input_field.setEnabled(False)
        self.input_field.setFixedHeight(60)
        self.input_field.setStyleSheet(f"""
            QLineEdit {{
                background: {BG_INPUT};
                border: 1px solid {BORDER};
                border-radius: 8px;
                color: {TEXT_MAIN};
                padding: 0 18px;
                font-size: 17px;
            }}
            QLineEdit:focus {{
                border: 1px solid {ACCENT};
            }}
            QLineEdit:disabled {{
                color: {TEXT_DIM};
            }}
        """)
        self.input_field.returnPressed.connect(self._send_message)

        self.send_btn = QPushButton("SEND  ⬆")
        self.send_btn.setEnabled(False)
        self.send_btn.setFixedSize(150, 60)
        self.send_btn.setCursor(Qt.PointingHandCursor)
        self.send_btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {ACCENT}, stop:1 {ACCENT2});
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 700;
                letter-spacing: 1px;
            }}
            QPushButton:disabled {{
                background: {BORDER};
                color: {TEXT_DIM};
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #00b8d9, stop:1 #6d28d9);
            }}
        """)
        self.send_btn.clicked.connect(self._send_message)

        input_row.addWidget(self.input_field)
        input_row.addWidget(self.send_btn)
        chat_col.addLayout(input_row)

        body.addLayout(chat_col)

        # Right: timing panel
        self.timing_panel = TimingPanel()
        body.addWidget(self.timing_panel)

        root.addLayout(body)

    # ─────────────────────────────────────────
    # SEND MESSAGE
    # ─────────────────────────────────────────

    def _send_message(self):
        text = self.input_field.text().strip()
        if not text:
            return
        self.input_field.clear()

        # Send via client (returns enc times)
        result = self.client.send_message(text)
        if result is None:
            return

        aes_enc_time, ecc_enc_time = result

        # Show own message immediately (with enc times; dec=0 for sender)
        timing = {
            'aes_enc': aes_enc_time,
            'aes_dec': 0.0,
            'ecc_enc': ecc_enc_time,
            'ecc_dec': 0.0,
        }
        self._add_bubble(self.username, text, timing, is_self=True)
        self.timing_panel.update_timing(timing)

    # ─────────────────────────────────────────
    # ADD MESSAGE BUBBLE
    # ─────────────────────────────────────────

    def _add_bubble(self, sender, text, timing, is_self=False, is_system=False):
        bubble = MessageBubble(sender, text, timing, is_self=is_self, is_system=is_system)
        # Insert before the trailing stretch
        count = self.messages_layout.count()
        self.messages_layout.insertWidget(count - 1, bubble)
        # Auto-scroll to bottom
        QTimer.singleShot(50, self._scroll_to_bottom)

    def _scroll_to_bottom(self):
        sb = self.scroll_area.verticalScrollBar()
        sb.setValue(sb.maximum())

    def closeEvent(self, event):
        self.client.disconnect()
        event.accept()


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def launch_gui():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(BG_DARK))
    palette.setColor(QPalette.WindowText, QColor(TEXT_MAIN))
    palette.setColor(QPalette.Base, QColor(BG_INPUT))
    palette.setColor(QPalette.AlternateBase, QColor(BG_MID))
    palette.setColor(QPalette.Text, QColor(TEXT_MAIN))
    palette.setColor(QPalette.Button, QColor(BG_MID))
    palette.setColor(QPalette.ButtonText, QColor(TEXT_MAIN))
    app.setPalette(palette)

    login = LoginDialog()
    if login.exec_() != QDialog.Accepted:
        sys.exit(0)

    window = ChatWindow(login.username)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    launch_gui()
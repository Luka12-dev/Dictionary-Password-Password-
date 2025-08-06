import sys
import hashlib
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QTextEdit, QProgressBar, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class CrackerThread(QThread):
    progress_update = pyqtSignal(int)
    result_found = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, dictionary_path, target_hash):
        super().__init__()
        self.dictionary_path = dictionary_path
        self.target_hash = target_hash.lower()
        self._is_running = True

    def run(self):
        try:
            with open(self.dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                total = len(lines)

                for index, line in enumerate(lines):
                    if not self._is_running:
                        break
                    password = line.strip()
                    hashed = hashlib.md5(password.encode()).hexdigest()
                    if hashed == self.target_hash:
                        self.result_found.emit(password)
                        break
                    self.progress_update.emit(int((index + 1) / total * 100))
        except Exception as e:
            self.result_found.emit(f"Error: {str(e)}")

        self.finished.emit()

    def stop(self):
        self._is_running = False


class PasswordCrackerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dictionary Password Cracker (MD5) - PyQt6")
        self.setGeometry(300, 300, 500, 400)
        self.setup_ui()
        self.cracker_thread = None
        self.dictionary_path = ""

    def setup_ui(self):
        layout = QVBoxLayout()

        self.label1 = QLabel("Enter MD5 hash to crack:")
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Example: 5f4dcc3b5aa765d61d8327deb882cf99")

        self.load_dict_btn = QPushButton("Load Dictionary File")
        self.load_dict_btn.clicked.connect(self.load_dictionary)

        self.dict_label = QLabel("No dictionary loaded")

        self.start_btn = QPushButton("Start Cracking")
        self.start_btn.clicked.connect(self.start_cracking)
        self.start_btn.setEnabled(False)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)

        layout.addWidget(self.label1)
        layout.addWidget(self.hash_input)
        layout.addWidget(self.load_dict_btn)
        layout.addWidget(self.dict_label)
        layout.addWidget(self.start_btn)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.result_text)

        self.setLayout(layout)

    def load_dictionary(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Dictionary File", "", "Text Files (*.txt);;All Files (*)")
        if path:
            self.dictionary_path = path
            self.dict_label.setText(f"Loaded: {path}")
            self.start_btn.setEnabled(True)

    def start_cracking(self):
        target_hash = self.hash_input.text().strip()
        if not target_hash or len(target_hash) != 32:
            QMessageBox.warning(self, "Invalid Hash", "Please enter a valid 32-character MD5 hash.")
            return
        if not self.dictionary_path:
            QMessageBox.warning(self, "No Dictionary", "Please load a dictionary file first.")
            return

        self.result_text.clear()
        self.progress_bar.setValue(0)
        self.start_btn.setEnabled(False)
        self.load_dict_btn.setEnabled(False)

        self.cracker_thread = CrackerThread(self.dictionary_path, target_hash)
        self.cracker_thread.progress_update.connect(self.progress_bar.setValue)
        self.cracker_thread.result_found.connect(self.display_result)
        self.cracker_thread.finished.connect(self.finish_cracking)
        self.cracker_thread.start()

    def display_result(self, result):
        if result.startswith("Error:"):
            self.result_text.append(result)
        else:
            self.result_text.append(f"Password found: {result}")

    def finish_cracking(self):
        self.start_btn.setEnabled(True)
        self.load_dict_btn.setEnabled(True)
        self.result_text.append("Cracking finished.")

    def closeEvent(self, event):
        if self.cracker_thread and self.cracker_thread.isRunning():
            self.cracker_thread.stop()
            self.cracker_thread.wait()
        event.accept()


def main():
    app = QApplication(sys.argv)
    window = PasswordCrackerApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

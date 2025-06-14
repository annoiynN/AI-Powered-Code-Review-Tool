import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import requests
import base64
import tempfile
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QTextEdit, QLabel, QFileDialog, 
                           QComboBox, QMessageBox, QProgressBar, QSplitter)
from PyQt5.QtGui import QFont, QTextCharFormat, QColor, QSyntaxHighlighter, QTextCursor
from PyQt5.QtCore import Qt, QRegExp, QThread, pyqtSignal

# URL API
API_URL = "http://127.0.0.1:8026" 

class PythonHighlighter(QSyntaxHighlighter):
    """Подсветка синтаксиса Python"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.highlighting_rules = []
        
        # Ключевые слова
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#CC7832"))
        keyword_format.setFontWeight(QFont.Bold)
        
        keywords = ["and", "as", "assert", "break", "class", "continue", "def", 
                   "del", "elif", "else", "except", "finally", "for", "from", 
                   "global", "if", "import", "in", "is", "lambda", "not", "or", 
                   "pass", "raise", "return", "try", "while", "with", "yield"]
        
        for word in keywords:
            pattern = QRegExp(f"\\b{word}\\b")
            self.highlighting_rules.append((pattern, keyword_format))
        
        # Строки
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#6A8759"))
        self.highlighting_rules.append((QRegExp("\".*\""), string_format))
        self.highlighting_rules.append((QRegExp("'.*'"), string_format))
        
        # Функции
        function_format = QTextCharFormat()
        function_format.setForeground(QColor("#FFC66D"))
        self.highlighting_rules.append((QRegExp("\\b[A-Za-z0-9_]+(?=\\()"), function_format))
        
        # Комментарии
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#808080"))
        self.highlighting_rules.append((QRegExp("#[^\n]*"), comment_format))
        
        # Числа
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#6897BB"))
        self.highlighting_rules.append((QRegExp("\\b[0-9]+\\b"), number_format))
    
    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)

class AnalysisThread(QThread):
    """Выполняет анализ кода в отдельном потоке"""
    analysis_complete = pyqtSignal(dict)
    analysis_error = pyqtSignal(str)
    
    def __init__(self, code, language, generate_pdf=False):
        super().__init__()
        self.code = code
        self.language = language
        self.generate_pdf = generate_pdf
    
    def run(self):
        try:
            if self.generate_pdf:
                endpoint = f"{API_URL}/analyze_with_pdf"
            else:
                endpoint = f"{API_URL}/analyze"
                
            response = requests.post(
                endpoint,
                json={
                    "code": self.code,
                    "language": self.language,
                    "generate_pdf": self.generate_pdf
                }
            )
            
            if response.status_code == 200:
                self.analysis_complete.emit(response.json())
            else:
                self.analysis_error.emit(f"Error: {response.status_code} - {response.text}")
        except Exception as e:
            self.analysis_error.emit(f"Connection error: {str(e)}")

class CodeEditorTab(QWidget):
    """Вкладка с редактором кода"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Верхняя панель
        top_layout = QHBoxLayout()
        
        self.language_selector = QComboBox()
        self.language_selector.addItem("Python")
        self.language_selector.addItem("JavaScript")
        self.language_selector.addItem("Java")
        
        top_layout.addWidget(QLabel("Language:"))
        top_layout.addWidget(self.language_selector)
        
        self.load_btn = QPushButton("Load File")
        self.load_btn.clicked.connect(self.load_file)
        top_layout.addWidget(self.load_btn)
        
        self.analyze_btn = QPushButton("Analyze Code")
        self.analyze_btn.clicked.connect(self.analyze_code)
        top_layout.addWidget(self.analyze_btn)
        
        self.analyze_pdf_btn = QPushButton("Analyze & Generate PDF")
        self.analyze_pdf_btn.clicked.connect(lambda: self.analyze_code(True))
        top_layout.addWidget(self.analyze_pdf_btn)
        
        top_layout.addStretch()
        
        layout.addLayout(top_layout)
        
        # Основной сплиттер
        splitter = QSplitter(Qt.Horizontal)
        
        # Редактор кода
        self.code_editor = QTextEdit()
        self.code_editor.setFont(QFont("Courier New", 10))
        self.highlighter = PythonHighlighter(self.code_editor.document())
        splitter.addWidget(self.code_editor)
        
        # Панель результатов
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        
        results_layout.addWidget(QLabel("Analysis Results:"))
        results_layout.addWidget(self.results_text)
        
        splitter.addWidget(results_widget)
        
        # Установка начальных размеров сплиттера
        splitter.setSizes([int(self.width() * 0.6), int(self.width() * 0.4)])
        
        layout.addWidget(splitter)
        
        # Статус-бар
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Ready")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.progress_bar)
        
        layout.addLayout(status_layout)
        
        self.setLayout(layout)
        
        # Пример кода
        self.code_editor.setText("""def example_function(a, b):
    # This is a sample function
    x = 10
    result = a / b  # Potential division by zero
    return result

# Main code
if __name__ == "__main__":
    example_function(5, 0)
""")
    
    def load_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Code File", "", "Python Files (*.py);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    self.code_editor.setText(file.read())
                self.status_label.setText(f"Loaded: {os.path.basename(file_path)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not load file: {str(e)}")
    
    def analyze_code(self, generate_pdf=False):
        code = self.code_editor.toPlainText()
        if not code.strip():
            QMessageBox.warning(self, "Empty Code", "Please enter or load some code first.")
            return
        
        language = self.language_selector.currentText().lower()
        
        # Показать индикатор загрузки
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Бесконечный прогресс
        self.status_label.setText("Analyzing code...")
        self.analyze_btn.setEnabled(False)
        self.analyze_pdf_btn.setEnabled(False)
        
        # Запустить анализ в отдельном потоке
        self.analysis_thread = AnalysisThread(code, language, generate_pdf)
        self.analysis_thread.analysis_complete.connect(self.handle_analysis_results)
        self.analysis_thread.analysis_error.connect(self.handle_analysis_error)
        self.analysis_thread.finished.connect(self.analysis_completed)
        self.analysis_thread.start()
    
    def handle_analysis_results(self, response_data):
        """Processes the results of the analysis and displays them in the interface."""
        try:
            # Очистка предыдущих результатов
            self.results_text.clear()
            
            # Заголовок отчета
            report = "Code analysis is complete\n\n"
            
            # Обработка структуры кода
            if "code_structure" in response_data:
                structure = response_data["code_structure"]
                
                # Функции
                if "functions" in structure and structure["functions"]:
                    report += "functions:\n"
                    for func in structure["functions"]:
                        # Проверяем наличие ключа 'line_number' или 'lineno'
                        line_number = func.get('line_number', func.get('lineno', 'N/A'))
                        report += f"- {func['name']} (line {line_number})\n"
                    report += "\n"
                    
                # Классы
                if "classes" in structure and structure["classes"]:
                    report += "classes:\n"
                    for cls in structure["classes"]:
                        # Проверяем наличие ключа 'line_number' или 'lineno'
                        line_number = cls.get('line_number', cls.get('lineno', 'N/A'))
                        report += f"- {cls['name']} (line {line_number})\n"
                    report += "\n"
                
                # Импорты
                if "imports" in structure and structure["imports"]:
                    report += "imports:\n"
                    for imp in structure["imports"]:
                        report += f"- {imp}\n"
                    report += "\n"
            
            # Обработка ошибок
            if "errors" in response_data and response_data["errors"]:
                errors = response_data["errors"]
                report += f"Found {len(errors)} problems in the code:\n\n"
                
                for i, error in enumerate(errors, 1):
                    report += f"{i}. {error['message']}\n"
                    report += f"   type: {error['type']}\n"
                    report += f"   line_start: {error['line_start']}"
                    if error.get('line_end') and error['line_end'] != error['line_start']:
                        report += f"-{error['line_end']}"
                    report += "\n"
                    
                    if error.get('category'):
                        report += f"   category: {error['category']}\n"
                        
                    if error.get('severity'):
                        report += f"   severity: {error['severity']}\n"
                        
                    if error.get('suggestion'):
                        report += f"   suggestion: {error['suggestion']}\n"
                        
                    if error.get('affected_code'):
                        report += f"   affected code: {error['affected_code']}\n"
                        
                    report += "\n"
            else:
                report += "No problems detected in the code.\n\n"
                
            # Рекомендации по улучшению
            if "recommendations" in response_data and response_data["recommendations"]:
                recommendations = response_data["recommendations"]
                report += f"recommendations({len(recommendations)}):\n\n"
                
                for i, rec in enumerate(recommendations, 1):
                    if isinstance(rec, dict) and 'suggested_fix' in rec:
                        report += f"{i}. {rec['suggested_fix']}\n\n"
                    elif hasattr(rec, 'suggested_fix'):
                        report += f"{i}. {rec.suggested_fix}\n\n"
                    else:
                        report += f"{i}. {str(rec)}\n\n"
            
            # Проверка на PDF
            if "pdf_content" in response_data and response_data["pdf_content"]:
                pdf_data = base64.b64decode(response_data["pdf_content"])
                
                # Сохраняем PDF во временный файл
                with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                    temp_file.write(pdf_data)
                    pdf_path = temp_file.name
                
                report += f"PDF saved to: {pdf_path}\n"
                self.status_label.setText(f"PDF saved to: {pdf_path}")
            
            # Отображение отчета
            self.results_text.setText(report)
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error in processing results: {str(e)}")
            import traceback
            traceback.print_exc()  # Выводим полный стек ошибки в консоль для отладки
        
    def handle_analysis_error(self, error_message):
        QMessageBox.critical(self, "Analysis Error", error_message)
        self.status_label.setText("Analysis failed. See error message.")
    
    def analysis_completed(self):
        # Сбрасываем индикаторы загрузки
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.analyze_pdf_btn.setEnabled(True)
        
        if not self.status_label.text().startswith("PDF saved to"):
            self.status_label.setText("Analysis completed")
    
def handle_analysis_results(self, response_data):
    """Processes the results of the analysis and displays them in the interface."""
    try:
        # Очистка предыдущих результатов
        self.results_text.clear()
        
        # Заголовок отчета
        report = "Code analysis is complete\n\n"
        
        # Обработка структуры кода
        if "code_structure" in response_data:
            structure = response_data["code_structure"]
            
            # Функции
            if "functions" in structure and structure["functions"]:
                report += "Functions found:\n"
                for func in structure["functions"]:
                    # Проверяем наличие ключа 'line_number' или 'lineno'
                    line_number = func.get('line_number', func.get('lineno', 'N/A'))
                    report += f"- {func['name']} (line {line_number})\n"
                report += "\n"
                
            # Классы
            if "classes" in structure and structure["classes"]:
                report += "Classes found:\n"
                for cls in structure["classes"]:
                    # Проверяем наличие ключа 'line_number' или 'lineno'
                    line_number = cls.get('line_number', cls.get('lineno', 'N/A'))
                    report += f"- {cls['name']} (line {line_number})\n"
                report += "\n"
            
            # Импорты
            if "imports" in structure and structure["imports"]:
                report += "Imported modules:\n"
                for imp in structure["imports"]:
                    report += f"- {imp}\n"
                report += "\n"
        
        # Обработка ошибок
        if "errors" in response_data and response_data["errors"]:
            errors = response_data["errors"]
            report += f"Found {len(errors)} problems in the code:\n\n"
            
            for i, error in enumerate(errors, 1):
                report += f"{i}. {error['message']}\n"
                report += f"   type: {error['type']}\n"
                report += f"   line number: {error['line_start']}"
                if error.get('line_end') and error['line_end'] != error['line_start']:
                    report += f"-{error['line_end']}"
                report += "\n"
                
                if error.get('category'):
                    report += f"   Category: {error['category']}\n"
                    
                if error.get('severity'):
                    report += f"   Severity: {error['severity']}\n"
                    
                if error.get('suggestion'):
                    report += f"   Suggestion: {error['suggestion']}\n"
                    
                if error.get('affected_code'):
                    report += f"   Affected code: {error['affected_code']}\n"
                    
                report += "\n"
        else:
            report += "No problems detected in the code.\n\n"
            
        # Рекомендации по улучшению
        if "recommendations" in response_data and response_data["recommendations"]:
            recommendations = response_data["recommendations"]
            report += f"Recommendations for improvement ({len(recommendations)}):\n\n"
            
            for i, rec in enumerate(recommendations, 1):
                if isinstance(rec, dict) and 'suggested_fix' in rec:
                    report += f"{i}. {rec['suggested_fix']}\n\n"
                elif hasattr(rec, 'suggested_fix'):
                    report += f"{i}. {rec.suggested_fix}\n\n"
                else:
                    report += f"{i}. {str(rec)}\n\n"
        
        # Проверка на PDF
        if "pdf_content" in response_data and response_data["pdf_content"]:
            pdf_data = base64.b64decode(response_data["pdf_content"])
            
            # Сохраняем PDF во временный файл
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                temp_file.write(pdf_data)
                pdf_path = temp_file.name
            
            report += f"PDF-отчет сохранен в: {pdf_path}\n"
            self.status_label.setText(f"PDF saved to: {pdf_path}")
        
        # Отображение отчета
        self.results_text.setText(report)
        
    except Exception as e:
        QMessageBox.critical(self, "Error", f"Ошибка при обработке результатов: {str(e)}")
        import traceback
        traceback.print_exc()  # Выводим полный стек ошибки в консоль для отладки
    
    def handle_analysis_error(self, error_message):
        QMessageBox.critical(self, "Analysis Error", error_message)
        self.status_label.setText("Analysis failed. See error message.")
    
    def analysis_completed(self):
        # Сбрасываем индикаторы загрузки
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        self.analyze_pdf_btn.setEnabled(True)
        
        if not self.status_label.text().startswith("PDF saved to"):
            self.status_label.setText("Analysis completed")

class MainWindow(QMainWindow):
    """Главное окно приложения"""
    
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("AI Code Reviewer")
        self.setGeometry(100, 100, 1200, 800)
        
        self.init_ui()
    
    def init_ui(self):
        # Основной виджет с вкладками
        self.tabs = QTabWidget()
        
        # Добавляем первую вкладку
        self.code_tab = CodeEditorTab()
        self.tabs.addTab(self.code_tab, "Code Analysis")
        
        # Устанавливаем вкладки как центральный виджет
        self.setCentralWidget(self.tabs)
        
        # Меню
        self.create_menus()
    
    def create_menus(self):
        # Основное меню
        menu_bar = self.menuBar()
        
        # Меню файл
        file_menu = menu_bar.addMenu("File")
        
        new_action = file_menu.addAction("New Tab")
        new_action.triggered.connect(self.add_new_tab)
        
        file_menu.addSeparator()
        
        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)
        
        # Меню "Помощь"
        help_menu = menu_bar.addMenu("Help")
        
        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self.show_about)
        
        api_action = help_menu.addAction("API Settings")
        api_action.triggered.connect(self.show_api_settings)
    
    def add_new_tab(self):
        """Добавляет новую вкладку редактора кода"""
        new_tab = CodeEditorTab()
        tab_index = self.tabs.addTab(new_tab, f"Code Analysis {self.tabs.count() + 1}")
        self.tabs.setCurrentIndex(tab_index)
    
    def show_about(self):
        """Показывает окно с информацией о программе"""
        QMessageBox.about(
            self,
            "About AI Code Reviewer",
            """<h3>AI Code Reviewer</h3>
            <p>Version 1.0</p>
            <p>A tool for analyzing code quality and identifying potential issues using AI.</p>
            <p>The application sends code to an AI backend that performs static analysis 
            and provides recommendations for improvements.</p>
            <p>© 2025 Your Company</p>"""
        )
    
    def show_api_settings(self):
        """Показывает окно настроек API"""
        global API_URL
        
        # Создаем диалоговое окно
        dialog = QWidget()
        dialog.setWindowTitle("API Settings")
        dialog.setMinimumWidth(400)
        
        layout = QVBoxLayout()
        
        # Поле для ввода адреса API
        layout.addWidget(QLabel("API URL:"))
        api_input = QTextEdit()
        api_input.setPlainText(API_URL)
        api_input.setMaximumHeight(50)
        layout.addWidget(api_input)
        
        # Кнопки
        buttons_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        test_btn = QPushButton("Test Connection")
        
        buttons_layout.addWidget(test_btn)
        buttons_layout.addStretch()
        buttons_layout.addWidget(save_btn)
        buttons_layout.addWidget(cancel_btn)
        
        layout.addLayout(buttons_layout)
        
        dialog.setLayout(layout)
        
        # Функции для кнопок
        def save_settings():
            global API_URL
            API_URL = api_input.toPlainText().strip()
            QMessageBox.information(dialog, "Settings Saved", "API URL has been updated.")
            dialog.close()
        
        def test_connection():
            url = api_input.toPlainText().strip()
            try:
                response = requests.get(f"{url}/health")
                if response.status_code == 200:
                    QMessageBox.information(dialog, "Connection Test", "Connection successful!")
                else:
                    QMessageBox.warning(
                        dialog, 
                        "Connection Test", 
                        f"Connection failed. Status code: {response.status_code}"
                    )
            except Exception as e:
                QMessageBox.critical(dialog, "Connection Test", f"Connection error: {str(e)}")
        
        # Подключаем функции к кнопкам
        save_btn.clicked.connect(save_settings)
        cancel_btn.clicked.connect(dialog.close)
        test_btn.clicked.connect(test_connection)
        
        # Показываем диалог как модальное окно
        dialog.setWindowModality(Qt.ApplicationModal)
        dialog.show()


def main():
    """Основная функция для запуска приложения"""
    app = QApplication(sys.argv)
    
    # Устанавливаем стиль
    app.setStyle("Fusion")
    
    # Создаем и показываем основное окно
    window = MainWindow()
    window.show()
    
    # Запускаем цикл событий
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
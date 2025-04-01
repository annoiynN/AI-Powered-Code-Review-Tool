from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from io import BytesIO
import datetime
from .models import CodeAnalysisResponse

class PDFReportGenerator:
    """Класс для генерации PDF-отчетов с результатами анализа кода"""
    
    @staticmethod
    def generate_report(analysis_result: CodeAnalysisResponse, code_text: str) -> BytesIO:
        """
        Генерирует PDF-отчет с результатами анализа
        
        Args:
            analysis_result: объект с результатами анализа
            code_text: исходный код для анализа
            
        Returns:
            BytesIO: буфер с PDF-документом
        """
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        
        # Стили
        styles = getSampleStyleSheet()
        title_style = styles['Heading1']
        subtitle_style = styles['Heading2']
        normal_style = styles['Normal']
        
        # Создаем пользовательский стиль для кода
        code_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            leftIndent=20,
        )
        
        # Заголовок отчета
        elements.append(Paragraph("AI Code Review Report", title_style))
        elements.append(Spacer(1, 0.25 * inch))
        
        # Дата и время
        date_text = f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        elements.append(Paragraph(date_text, normal_style))
        elements.append(Spacer(1, 0.25 * inch))
        
        # Исходный код
        elements.append(Paragraph("Source Code:", subtitle_style))
        formatted_code = code_text.replace('\n', '<br/>').replace(' ', '&nbsp;')
        elements.append(Paragraph(formatted_code, code_style))
        elements.append(Spacer(1, 0.25 * inch))
        
        # Структура кода
        elements.append(Paragraph("Code Structure", subtitle_style))
        
        # Функции
        if analysis_result.code_structure.functions:
            elements.append(Paragraph("Functions:", styles['Heading3']))
            function_data = [["Name", "Line", "Documentation"]]
            for func in analysis_result.code_structure.functions:
                function_data.append([func.get('name', ''), 
                                     str(func.get('line_number', '')), 
                                     func.get('docstring', '')[:50]])
            
            function_table = Table(function_data, colWidths=[2*inch, 1*inch, 3*inch])
            function_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(function_table)
            elements.append(Spacer(1, 0.15 * inch))
        
        # Классы
        if analysis_result.code_structure.classes:
            elements.append(Paragraph("Classes:", styles['Heading3']))
            class_data = [["Name", "Line", "Documentation"]]
            for cls in analysis_result.code_structure.classes:
                class_data.append([cls.get('name', ''), 
                                  str(cls.get('line_number', '')), 
                                  cls.get('docstring', '')[:50]])
            
            class_table = Table(class_data, colWidths=[2*inch, 1*inch, 3*inch])
            class_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(class_table)
            elements.append(Spacer(1, 0.15 * inch))
            
        # Ошибки
        elements.append(Paragraph("Detected Errors", subtitle_style))
        if analysis_result.errors:
            error_data = [["Type", "Line", "Severity", "Message"]]
            for error in analysis_result.errors:
                error_data.append([
                    error.type, 
                    str(error.line), 
                    error.severity,
                    error.message
                ])
            
            error_table = Table(error_data, colWidths=[1.5*inch, 0.7*inch, 1*inch, 3*inch])
            error_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('ALIGN', (3, 1), (3, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                # Выделение ошибок в зависимости от тяжести
                ('BACKGROUND', (2, 1), (2, -1), colors.white),
            ]))
            
            # Настройка цветов по тяжести
            for i, error in enumerate(analysis_result.errors, 1):
                if error.severity == 'error' or error.severity == 'fatal':
                    error_table.setStyle(TableStyle([
                        ('BACKGROUND', (2, i), (2, i), colors.lightcoral)
                    ]))
                elif error.severity == 'warning':
                    error_table.setStyle(TableStyle([
                        ('BACKGROUND', (2, i), (2, i), colors.lightyellow)
                    ]))
            
            elements.append(error_table)
        else:
            elements.append(Paragraph("No errors detected.", normal_style))
        
        elements.append(Spacer(1, 0.25 * inch))
        
        # Рекомендации
        elements.append(Paragraph("Recommendations", subtitle_style))
        if analysis_result.recommendations:
            for i, rec in enumerate(analysis_result.recommendations, 1):
                elements.append(Paragraph(f"Recommendation #{i}:", styles['Heading4']))
                elements.append(Paragraph(f"Error: {rec.original_error.message} (line {rec.original_error.line})", normal_style))
                elements.append(Paragraph(f"Suggested Fix:", normal_style))
                elements.append(Paragraph(rec.suggested_fix, code_style))
                elements.append(Spacer(1, 0.15 * inch))
        else:
            elements.append(Paragraph("No recommendations available.", normal_style))
        
        # Подвал
        elements.append(Spacer(1, 0.5 * inch))
        elements.append(Paragraph("Generated by AI Code Reviewer", 
                                  ParagraphStyle(name='Footer', alignment=1)))
        
        # Собираем PDF
        doc.build(elements)
        buffer.seek(0)
        return buffer
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from io import BytesIO
import datetime
from .models import CodeAnalysisResponse

class PDFReportGenerator:
    
    @staticmethod
    def generate_report(analysis_result: CodeAnalysisResponse, code_text: str) -> BytesIO:

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []

        styles = getSampleStyleSheet()
        title_style = styles['Heading1']
        subtitle_style = styles['Heading2']
        normal_style = styles['Normal']

        code_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            leftIndent=20,
        )

        elements.append(Paragraph("AI Code Review Report", title_style))
        elements.append(Spacer(1, 0.25 * inch))

        date_text = f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        elements.append(Paragraph(date_text, normal_style))
        elements.append(Spacer(1, 0.25 * inch))

        elements.append(Paragraph("Source Code:", subtitle_style))
        formatted_code = code_text.replace('\n', '<br/>').replace(' ', '&nbsp;')
        elements.append(Paragraph(formatted_code, code_style))
        elements.append(Spacer(1, 0.25 * inch))

        elements.append(Paragraph("Code Structure", subtitle_style))

        if analysis_result.code_structure.functions:
            elements.append(Paragraph("Functions:", styles['Heading3']))
            function_data = [["Name", "Line", "Documentation"]]
            for func in analysis_result.code_structure.functions:
                # Проверяем наличие ключа 'line_number' или 'lineno'
                line_number = func.get('line_number', func.get('lineno', 'N/A'))
                function_data.append([
                    func.get('name', ''), 
                    str(line_number), 
                    func.get('docstring', '')[:50] if func.get('docstring') else ''
                ])
            
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

        if analysis_result.code_structure.classes:
            elements.append(Paragraph("Classes:", styles['Heading3']))
            class_data = [["Name", "Line", "Documentation"]]
            for cls in analysis_result.code_structure.classes:
                # Проверяем наличие ключа 'line_number' или 'lineno'
                line_number = cls.get('line_number', cls.get('lineno', 'N/A'))
                class_data.append([
                    cls.get('name', ''), 
                    str(line_number), 
                    cls.get('docstring', '')[:50] if cls.get('docstring') else ''
                ])
            
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

        elements.append(Paragraph("Detected Errors", subtitle_style))
        if analysis_result.errors:
            error_data = [["Type", "Line", "Severity", "Message"]]
            for error in analysis_result.errors:
                error_data.append([
                    error.type, 
                    str(error.line_start),  # Исправление: используем line_start вместо line
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
                ('BACKGROUND', (2, 1), (2, -1), colors.white),
            ]))

            # Создаем отдельную таблицу стилей для цветов
            color_styles = []
            for i, error in enumerate(analysis_result.errors, 1):
                severity = error.severity.lower() if isinstance(error.severity, str) else ''
                if severity == 'critical' or severity == 'high':
                    color_styles.append(('BACKGROUND', (2, i), (2, i), colors.lightcoral))
                elif severity == 'medium' or severity == 'warning':
                    color_styles.append(('BACKGROUND', (2, i), (2, i), colors.lightyellow))
                elif severity == 'low' or severity == 'info':
                    color_styles.append(('BACKGROUND', (2, i), (2, i), colors.lightblue))
            
            if color_styles:
                error_table.setStyle(TableStyle(color_styles))
            
            elements.append(error_table)
        else:
            elements.append(Paragraph("No errors detected.", normal_style))
        
        elements.append(Spacer(1, 0.25 * inch))

        elements.append(Paragraph("Recommendations", subtitle_style))
        if analysis_result.recommendations:
            for i, rec in enumerate(analysis_result.recommendations, 1):
                elements.append(Paragraph(f"Recommendation #{i}:", styles['Heading4']))
                # Получаем поле line_start вместо line
                line_num = getattr(rec.original_error, 'line_start', 'N/A')
                elements.append(Paragraph(f"Error: {rec.original_error.message} (line {line_num})", normal_style))
                elements.append(Paragraph(f"Suggested Fix:", normal_style))
                elements.append(Paragraph(rec.suggested_fix, code_style))
                elements.append(Spacer(1, 0.15 * inch))
        else:
            elements.append(Paragraph("No recommendations available.", normal_style))

        elements.append(Spacer(1, 0.5 * inch))
        elements.append(Paragraph("Generated by AI Code Reviewer", 
                                  ParagraphStyle(name='Footer', alignment=1)))

        doc.build(elements)
        buffer.seek(0)
        return buffer
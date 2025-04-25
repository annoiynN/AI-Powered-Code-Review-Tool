import base64
from io import BytesIO
from .code_parser import CodeParser
from .error_detector import ErrorDetector
from .code_improver import CodeImprover
from .report_generator import PDFReportGenerator
from .models import CodeAnalysisRequest, CodeAnalysisResponse, CodeAnalysisResponseWithPDF, CodeStructureDetail

class CodeReviewService:
    def __init__(self):
        self.code_improver = CodeImprover()

    def review_python_code(self, request: CodeAnalysisRequest) -> CodeAnalysisResponse:
        """
        Анализирует код Python и возвращает результаты анализа
        """
        # Парсинг структуры кода
        code_structure_dict = CodeParser.parse_python_code(request.code)
        
        # Преобразование результата в формат, соответствующий модели
        code_structure = CodeStructureDetail(
            functions=code_structure_dict.get("functions", []),
            classes=code_structure_dict.get("classes", []),
            imports=code_structure_dict.get("imports", [])
        )
        
        # Обнаружение ошибок
        pattern_errors = ErrorDetector.detect_pattern_errors(request.code)
        pylint_errors = ErrorDetector.run_pylint_analysis(request.code)
        
        all_errors = pattern_errors + pylint_errors
        
        # Генерация рекомендаций
        recommendations = self.code_improver.generate_improvements(request.code, all_errors)
        
        return CodeAnalysisResponse(
            code_structure=code_structure,
            errors=all_errors,
            recommendations=recommendations
        )

    def review_with_pdf(self, request: CodeAnalysisRequest) -> CodeAnalysisResponseWithPDF:

        analysis_result = self.review_python_code(request)
        
        if request.generate_pdf:
            # Генерация PDF-отчета
            pdf_buffer = PDFReportGenerator.generate_report(analysis_result, request.code)
            # Кодирование PDF в base64 для передачи через JSON
            pdf_encoded = base64.b64encode(pdf_buffer.getvalue()).decode('utf-8')
            
            return CodeAnalysisResponseWithPDF(
                analysis=analysis_result,
                pdf_content=pdf_encoded
            )
        else:
            return CodeAnalysisResponseWithPDF(
                analysis=analysis_result,
                pdf_content=None
            )
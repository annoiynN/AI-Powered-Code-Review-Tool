import base64
from io import BytesIO
from .code_parser import CodeParser
from .error_detector import ErrorDetector
from .code_improver import CodeImprover
from .report_generator import PDFReportGenerator
from .models import CodeAnalysisRequest, CodeAnalysisResponse, CodeAnalysisResponseWithPDF, CodeStructureDetail, CodeError, RecommendationDetail

class CodeReviewService:
    def __init__(self):
        self.code_improver = CodeImprover()
        self.error_detector = ErrorDetector()

    def review_python_code(self, request: CodeAnalysisRequest) -> CodeAnalysisResponse:

        # Парсинг структуры кода
        code_structure_dict = CodeParser.parse_python_code(request.code)
        
        # Преобразование результата в формат, соответствующий модели
        code_structure = CodeStructureDetail(
            functions=code_structure_dict.get("functions", []),
            classes=code_structure_dict.get("classes", []),
            imports=code_structure_dict.get("imports", [])
        )
        
        # Обнаружение ошибок
        pattern_errors = self.error_detector.detect_pattern_errors(request.code)
        pylint_errors = self.error_detector.run_pylint_analysis(request.code)
        
        # Преобразование ошибок в Pydantic-модели
        pydantic_pattern_errors = [error.to_pydantic_model() for error in pattern_errors]
        pydantic_pylint_errors = [error.to_pydantic_model() for error in pylint_errors]
        
        all_errors = pydantic_pattern_errors + pydantic_pylint_errors
        
        # Генерация рекомендаций на основе оригинальных ошибок
        improver_recommendations = self.code_improver.generate_improvements(request.code, pattern_errors + pylint_errors)
        
        # Преобразование рекомендаций в Pydantic-модели
        pydantic_recommendations = []
        
        # Предполагаем, что generate_improvements возвращает список рекомендаций
        # Если формат другой, нужно адаптировать этот код
        for recommendation in improver_recommendations:
            # Преобразуем в соответствующую структуру RecommendationDetail
            if hasattr(recommendation, 'original_error') and hasattr(recommendation, 'suggested_fix'):
                # Если это уже правильный формат, просто преобразуем original_error в Pydantic
                original_error_pydantic = recommendation.original_error.to_pydantic_model() if hasattr(recommendation.original_error, 'to_pydantic_model') else recommendation.original_error
                
                pydantic_recommendations.append(RecommendationDetail(
                    original_error=original_error_pydantic,
                    suggested_fix=recommendation.suggested_fix
                ))
            elif isinstance(recommendation, dict) and 'original_error' in recommendation and 'suggested_fix' in recommendation:
                # Если это словарь с нужными ключами
                original_error = recommendation['original_error']
                original_error_pydantic = original_error.to_pydantic_model() if hasattr(original_error, 'to_pydantic_model') else original_error
                
                pydantic_recommendations.append(RecommendationDetail(
                    original_error=original_error_pydantic,
                    suggested_fix=recommendation['suggested_fix']
                ))
        
        return CodeAnalysisResponse(
            code_structure=code_structure,
            errors=all_errors,
            recommendations=pydantic_recommendations
        )

    def review_with_pdf(self, request: CodeAnalysisRequest) -> CodeAnalysisResponseWithPDF:

        analysis_result = self.review_python_code(request)
        
        if request.generate_pdf:
            pdf_buffer = PDFReportGenerator.generate_report(analysis_result, request.code)
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
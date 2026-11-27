from .a3e_result_tables import (
    TABLE_SPECS,
    THESIS_REFERENCE as REPORTING_THESIS_REFERENCE,
    generate_tables,
)
from .a3e_figures import (
    FIGURES,
    FigureSpec,
    reproduce_figures,
)
__all__ = [
    "FIGURES", "FigureSpec", "TABLE_SPECS",
    "REPORTING_THESIS_REFERENCE",
    "generate_tables", "reproduce_figures",
]

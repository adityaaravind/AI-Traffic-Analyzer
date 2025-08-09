import os
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape

def render_report(metrics: Dict[str, Any], ai_result: Dict[str, Any], ai_disabled: bool, capture_info: Dict[str, Any]) -> str:
    here = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    templates_dir = os.path.join(here, "templates")
    env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape()
    )
    template = env.get_template("report.html.j2")
    context = {
        "metrics": metrics,
        "ai": ai_result,
        "ai_disabled": ai_disabled,
        "capture": capture_info,
    }
    return template.render(**context)

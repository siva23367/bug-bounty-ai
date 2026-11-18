import html
import io
import json

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def sections(finding):
    return [
        ('Title', finding.title), ('Vulnerability category', finding.category),
        ('Affected endpoint', finding.endpoint), ('Severity', finding.severity),
        ('Verification status', finding.status), ('CVSS score', finding.cvss or 'Not scored; requires human assessment'),
        ('Eligibility', finding.eligibility), ('Description', finding.description),
        ('Reproduction steps', '\n'.join(f'{i + 1}. {s}' for i, s in enumerate(finding.steps))),
        ('Proof of concept', 'Only the inert marker, request variation or observation documented below was tested. '
         'Redacted query values must be supplied from your own authorized test data. No executable exploit is implied.'),
        ('Evidence', json.dumps(finding.evidence, indent=2)), ('Impact', finding.impact),
        ('Remediation', finding.remediation), ('Human review', finding.review_note or 'Not reviewed'),
        ('AI advisory', json.dumps(finding.ai_analysis, indent=2) if finding.ai_analysis else 'Not requested'),
        ('Disclosure', 'Potential findings are not verified vulnerabilities. Rewards and acceptance are never guaranteed. '
         'Submit only after reviewing program rules and validating impact with permitted test data.'),
    ]


def export(finding, format):
    entries = sections(finding)
    if format == 'md':
        # Escape target-controlled Markdown so opening a report cannot load remote images.
        def escape(value):
            value = html.escape(str(value))
            for char in ('\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '!', '|'):
                value = value.replace(char, '\\' + char)
            return value
        text = '\n\n'.join(f'## {title}\n\n{escape(value)}' for title, value in entries)
        return text.encode(), 'text/markdown; charset=utf-8'
    if format == 'html':
        text = '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>Security research report</title>'
        text += '<style>body{max-width:900px;margin:40px auto;font:16px system-ui;padding:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><body>'
        text += ''.join(f'<h2>{title}</h2><pre>{html.escape(str(value))}</pre>' for title, value in entries)
        return (text + '</body></html>').encode(), 'text/html; charset=utf-8'
    if format == 'pdf':
        buffer = io.BytesIO()
        document = SimpleDocTemplate(buffer, title='Security research report')
        styles = getSampleStyleSheet()
        story = []
        for title, value in entries:
            story.append(Paragraph(title, styles['Heading2']))
            for line in str(value).splitlines():
                story.append(Paragraph(html.escape(line), styles['BodyText']))
            story.append(Spacer(1, 10))
        document.build(story)
        return buffer.getvalue(), 'application/pdf'
    raise ValueError('Unsupported report format')

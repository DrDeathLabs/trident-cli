"""ReportLab Platypus PDF generation — executive/customer-ready security reports.

Structure (both scan and triage):
  Page 1   : Cover — dark full-bleed, target name, summary stats
  Page 2   : Table of Contents — auto-generated with dotted leaders + page numbers
  Page 3+  : Content sections — one PageBreak per section, KeepTogether finding cards
  All body pages: running header (report type + target, page N) and footer (Trident + CONFIDENTIAL)
"""

from __future__ import annotations

from html import escape as _he
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

from trident.clock import utcnow

# ── Layout ────────────────────────────────────────────────────────────────────
W, H = A4
ML = 2.2 * cm   # left/right margin
MB = 2.5 * cm   # bottom margin
MT = 3.0 * cm   # top margin (header zone)
BW = W - 2 * ML # body width
BH = H - MB - MT # usable body height

# ── Palette ───────────────────────────────────────────────────────────────────
C_DARK      = HexColor('#0f172a')
C_SLATE     = HexColor('#1e293b')
C_MUTED     = HexColor('#475569')
C_GRAY      = HexColor('#94a3b8')
C_BORDER    = HexColor('#e2e8f0')
C_CARD_BG   = HexColor('#fafafa')
C_TEXT      = HexColor('#334155')
C_ORANGE    = HexColor('#fb923c')
C_GREEN     = HexColor('#4ade80')
C_PURPLE    = HexColor('#7c3aed')

SEV_BG = {
    'critical': HexColor('#7f1d1d'), 'high':   HexColor('#7c2d12'),
    'medium':   HexColor('#78350f'), 'low':    HexColor('#0c4a6e'),
    'info':     HexColor('#1e293b'),
}
SEV_FG = {
    'critical': HexColor('#fca5a5'), 'high':   HexColor('#fdba74'),
    'medium':   HexColor('#fcd34d'), 'low':    HexColor('#7dd3fc'),
    'info':     HexColor('#94a3b8'),
}
TIER_SEV = {'P0': 'critical', 'P1': 'high', 'P2': 'medium', 'P3': 'low', 'P4': 'info'}
SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

def _safe(text) -> str:
    """Escape user-supplied text so ReportLab's XML paragraph parser doesn't choke on HTML tags."""
    return _he(str(text) if text is not None else '', quote=False)


FACTOR_LABELS = {
    'remote_unauth': 'Remote (no auth)', 'remote_auth': 'Remote (auth req.)',
    'adjacent': 'Adjacent', 'local': 'Local', 'physical': 'Physical',
    'rce': 'RCE', 'auth_bypass': 'Auth Bypass', 'data_exposure': 'Data Exposure',
    'data_tampering': 'Data Tampering', 'ssrf': 'SSRF', 'injection': 'Injection',
    'dos': 'DoS', 'info_disclosure': 'Info Disclosure', 'other': 'Other',
    'trivial': 'Trivial', 'moderate': 'Moderate', 'difficult': 'Difficult',
    'involved': 'Involved', 'reachable': 'Reachable', 'unreachable': 'Unreachable',
    'unknown': 'Unknown reach',
}


def _fl(v: str | None) -> str:
    return FACTOR_LABELS.get(v, (v or '').replace('_', ' ').title()) if v else ''


# ── Paragraph styles ──────────────────────────────────────────────────────────

def _ps(name: str, **kw) -> ParagraphStyle:
    return ParagraphStyle(name, **kw)


def _make_styles() -> dict:
    return {
        'h1':          _ps('TH1', fontName='Helvetica-Bold', fontSize=15, leading=19,
                            textColor=C_DARK, spaceBefore=16, spaceAfter=5),
        'h2':          _ps('TH2', fontName='Helvetica-Bold', fontSize=11, leading=14,
                            textColor=C_DARK),
        'loc':         _ps('TLoc', fontName='Courier', fontSize=8, leading=11, textColor=C_GRAY,
                            spaceAfter=2),
        'meta':        _ps('TMeta', fontName='Helvetica', fontSize=8, leading=10,
                            textColor=C_GRAY, spaceAfter=2),
        'body':        _ps('TBody', fontName='Helvetica', fontSize=10, leading=14,
                            textColor=C_TEXT, spaceAfter=4),
        'clabel':      _ps('TCLabel', fontName='Helvetica-Bold', fontSize=8, leading=10),
        'ctext':       _ps('TCText', fontName='Helvetica', fontSize=9, leading=13, textColor=C_TEXT),
        'frow':        _ps('TFRow', fontName='Helvetica', fontSize=9, leading=12, textColor=C_TEXT,
                            spaceAfter=2),
        'cover_label': _ps('TCovL', fontName='Helvetica', fontSize=9, leading=12, textColor=C_GRAY),
        'cover_type':  _ps('TCovT', fontName='Helvetica-Bold', fontSize=13, leading=16,
                            textColor=C_MUTED),
        'cover_title': _ps('TCovTi', fontName='Helvetica-Bold', fontSize=26, leading=31,
                            textColor=C_DARK, spaceAfter=6),
        'cover_meta':  _ps('TCovM', fontName='Helvetica', fontSize=10, leading=14, textColor=C_MUTED),
        'sec_main':    _ps('TSecM', fontName='Helvetica-Bold', fontSize=14, leading=18,
                            textColor=colors.white),
        'sec_sub':     _ps('TSecS', fontName='Helvetica', fontSize=9, leading=12, textColor=colors.white),
        'toc_head':    _ps('TTocH', fontName='Helvetica-Bold', fontSize=20, leading=24,
                            textColor=C_DARK, spaceAfter=14),
    }


# ── Document template ─────────────────────────────────────────────────────────

class _TridentDoc(BaseDocTemplate):
    def __init__(self, buf: BytesIO, report_type: str, target: str, generated: str):
        BaseDocTemplate.__init__(self, buf, pagesize=A4,
                                 leftMargin=0, rightMargin=0, topMargin=0, bottomMargin=0)
        self.report_type = report_type
        self.target = target
        self.generated = generated

        # Cover frame fills the dark-background page
        cover_frame = Frame(ML, MB, BW, H - MB - 1.5 * cm,
                            topPadding=0, bottomPadding=0, leftPadding=0, rightPadding=0,
                            id='cover')
        cover_tmpl = PageTemplate('Cover', frames=[cover_frame], onPage=self._draw_cover)

        # Body frame sits inside header/footer chrome
        body_frame = Frame(ML, MB, BW, BH,
                           topPadding=0, bottomPadding=0, leftPadding=0, rightPadding=0,
                           id='body')
        body_tmpl = PageTemplate('Body', frames=[body_frame], onPage=self._draw_body)

        self.addPageTemplates([cover_tmpl, body_tmpl])

    # ── Canvas callbacks ──────────────────────────────────────────────────────

    def _draw_cover(self, canvas, doc):
        canvas.saveState()
        # Thin accent bar at bottom only — no full-page fill (saves ink)
        canvas.setFillColor(C_DARK)
        canvas.rect(0, 0, W, 0.35 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_MUTED)
        canvas.setFont('Helvetica', 7.5)
        canvas.drawRightString(W - ML, 1.2 * cm, 'TRIDENT  ·  Security Intelligence Platform')
        canvas.restoreState()

    def _draw_body(self, canvas, doc):
        canvas.saveState()
        canvas.setLineWidth(0.5)
        canvas.setStrokeColor(C_BORDER)
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(C_GRAY)
        # Header
        hy = H - 2.2 * cm
        canvas.line(ML, hy, ML + BW, hy)
        canvas.drawString(ML, hy + 4, f'{self.report_type}  —  {self.target}')
        canvas.drawRightString(ML + BW, hy + 4, f'Page {doc.page}')
        # Footer
        fy = MB - 0.6 * cm
        canvas.line(ML, fy, ML + BW, fy)
        canvas.drawString(ML, fy - 10, f'Generated by Trident  ·  {self.generated}')
        canvas.drawRightString(ML + BW, fy - 10, 'CONFIDENTIAL')
        canvas.restoreState()

    # ── TOC hook ──────────────────────────────────────────────────────────────

    def afterFlowable(self, flowable):
        # Section bands carry a _toc_entry attribute set during story construction
        if isinstance(flowable, Table) and hasattr(flowable, '_toc_entry'):
            self.notify('TOCEntry', (0, flowable._toc_entry, self.page))


# ── TOC ───────────────────────────────────────────────────────────────────────

def _make_toc() -> TableOfContents:
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle('TocL0', fontName='Helvetica-Bold', fontSize=11, leading=18,
                       leftIndent=0, spaceAfter=1),
    ]
    toc.dotsMinLevel = 0
    return toc


# ── Horizontal rule ───────────────────────────────────────────────────────────

def _hr(color: HexColor | None = None, thickness: float = 0.5,
        space_before: float = 0, space_after: float = 4) -> HRFlowable:
    return HRFlowable(width=BW, thickness=thickness, color=color or C_BORDER,
                      spaceBefore=space_before, spaceAfter=space_after)


# ── Left-rule callout block ───────────────────────────────────────────────────

def _callout(label: str, text: str, bar_color: HexColor, styles: dict) -> Table:
    """2-column table: 3pt colored bar | label + body text."""
    bar_w = 3
    content_w = BW - bar_w - 8
    label_p = Paragraph(label.upper(), _ps('_cl', parent=styles['clabel'], textColor=bar_color))
    text_p = Paragraph(text, styles['ctext'])
    inner = Table([[label_p], [text_p]], colWidths=[content_w])
    inner.setStyle(TableStyle([
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
        ('TOPPADDING',    (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
    ]))
    outer = Table([[None, inner]], colWidths=[bar_w, BW - bar_w])
    outer.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (0, -1), bar_color),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 0),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
    ]))
    return outer


# ── Section band ─────────────────────────────────────────────────────────────

def _section_band(badge: str, label: str, bg: HexColor,
                  meta_lines: list[str], styles: dict) -> Table:
    """Colored full-width section header. Sets _toc_entry for TOC registration."""
    rows = [[Paragraph(f'{badge}  —  {label}', styles['sec_main'])]]
    for line in meta_lines:
        rows.append([Paragraph(line, styles['sec_sub'])])

    inner = Table(rows, colWidths=[BW - 3.2 * cm])
    inner.setStyle(TableStyle([
        ('TOPPADDING',    (0, 0), (-1, -1), 2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('LEFTPADDING',   (0, 0), (-1, -1), 0),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
    ]))
    band = Table([[inner]], colWidths=[BW])
    band.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), bg),
        ('TOPPADDING',    (0, 0), (-1, -1), 13),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 13),
        ('LEFTPADDING',   (0, 0), (-1, -1), 16),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 16),
    ]))
    band._toc_entry = f'{badge}  —  {label}'
    return band


# ── Badge table ───────────────────────────────────────────────────────────────

def _badge_col(text: str, bg: HexColor, fg: HexColor, width: float) -> tuple:
    """Returns (Table, width) for a colored badge cell."""
    p = Paragraph(text, _ps('_b', fontName='Helvetica-Bold', fontSize=8,
                             leading=10, textColor=fg, alignment=TA_CENTER))
    t = Table([[p]], colWidths=[width])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), bg),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING',   (0, 0), (-1, -1), 5),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 5),
    ]))
    return t


# ── Card: scan finding ────────────────────────────────────────────────────────

def _scan_card(f, styles: dict) -> KeepTogether:
    sev = (f.severity or 'info').lower()
    bg  = SEV_BG.get(sev, C_SLATE)
    fg  = SEV_FG.get(sev, C_GRAY)
    BAD = 1.9 * cm

    badge_p = Paragraph(sev.upper(), _ps('_b', fontName='Helvetica-Bold', fontSize=8,
                                          leading=10, textColor=fg, alignment=TA_CENTER))
    title_p = Paragraph(_safe(f.title or f.rule_id or '(unnamed)'), styles['h2'])
    hdr = Table([[badge_p, title_p]], colWidths=[BAD, BW - BAD])
    hdr.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (0, -1), bg),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING',   (0, 0), (0, -1), 6),
        ('RIGHTPADDING',  (0, 0), (0, -1), 6),
        ('LEFTPADDING',   (1, 0), (-1, -1), 10),
        ('RIGHTPADDING',  (1, 0), (-1, -1), 6),
    ]))

    elems: list = [hdr, _hr(thickness=0.3, space_after=5)]

    # Location
    loc = _safe(f'{f.file or ""}:{f.line_start or ""}')
    for part in [f.tool, f.confidence]:
        if part:
            loc += f'  ·  {_safe(part)}'
    elems.append(Paragraph(loc, styles['loc']))

    # CWE / OWASP / Rule
    meta = '  ·  '.join(x for x in [
        f'CWE: {_safe(f.cwe)}' if f.cwe else '',
        f'OWASP: {_safe(f.owasp)}' if f.owasp else '',
        f'Rule: {_safe(f.rule_id)}' if f.rule_id else '',
    ] if x)
    if meta:
        elems.append(Paragraph(meta, styles['meta']))

    if f.corroborating_tools:
        elems.append(Paragraph('Also flagged by: ' + ', '.join(_safe(t) for t in f.corroborating_tools), styles['meta']))

    if f.description:
        elems.append(Spacer(1, 5))
        elems.append(Paragraph(_safe(f.description), styles['body']))

    if f.narrative:
        elems.append(Spacer(1, 5))
        elems.append(_callout('Analysis', _safe(f.narrative), C_GRAY, styles))

    if f.exploit_scenario:
        elems.append(Spacer(1, 5))
        elems.append(_callout('How It Could Be Exploited', _safe(f.exploit_scenario), C_ORANGE, styles))

    if f.remediation:
        elems.append(Spacer(1, 5))
        elems.append(_callout('Remediation', _safe(f.remediation), C_GREEN, styles))

    if f.attack_paths:
        elems.append(Spacer(1, 5))
        paths = '<br/>'.join(f'{i}. {_safe(p)}' for i, p in enumerate(f.attack_paths, 1))
        elems.append(Paragraph('ATTACK PATHS', _ps('_apl', parent=styles['clabel'], textColor=C_GRAY)))
        elems.append(Paragraph(paths, styles['ctext']))

    elems.append(Spacer(1, 10))
    return KeepTogether(elems)


# ── Card: triage finding ──────────────────────────────────────────────────────

def _triage_card(f, override, tier: str, styles: dict) -> KeepTogether:
    triage   = f.triage or {}
    sev_key  = TIER_SEV.get(tier, 'info')
    tier_bg  = SEV_BG.get(sev_key, C_SLATE)
    tier_fg  = SEV_FG.get(sev_key, C_GRAY)
    sev2     = (f.severity or 'info').lower()
    sev_bg2  = SEV_BG.get(sev2, C_SLATE)
    sev_fg2  = SEV_FG.get(sev2, C_GRAY)

    T_W, S_W = 1.5 * cm, 1.8 * cm
    tier_p  = Paragraph(tier, _ps('_tb', fontName='Helvetica-Bold', fontSize=9,
                                   leading=11, textColor=tier_fg, alignment=TA_CENTER))
    sev_p   = Paragraph(sev2.upper(), _ps('_sb', fontName='Helvetica-Bold', fontSize=8,
                                           leading=10, textColor=sev_fg2, alignment=TA_CENTER))
    title_p = Paragraph(_safe(f.title or f.rule_id or '(unnamed)'), styles['h2'])

    hdr = Table([[tier_p, sev_p, title_p]], colWidths=[T_W, S_W, BW - T_W - S_W])
    hdr.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (0, -1), tier_bg),
        ('BACKGROUND',    (1, 0), (1, -1), sev_bg2),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING',   (0, 0), (1, -1), 4),
        ('RIGHTPADDING',  (0, 0), (1, -1), 4),
        ('LEFTPADDING',   (2, 0), (-1, -1), 10),
        ('RIGHTPADDING',  (2, 0), (-1, -1), 6),
    ]))

    elems: list = [hdr, _hr(thickness=0.3, space_after=5)]

    # Location
    loc = _safe(f'{f.file or ""}:{f.line_start or ""}  ·  {f.tool or ""}')
    elems.append(Paragraph(loc, styles['loc']))

    # Triage factors
    factors = '  |  '.join(x for x in [
        f'Vector: {_fl(triage.get("attack_vector"))}' if triage.get('attack_vector') else '',
        f'Impact: {_fl(triage.get("impact"))}' if triage.get('impact') else '',
        f'Exploitability: {_fl(triage.get("exploitability"))}' if triage.get('exploitability') else '',
        f'Fix effort: {_fl(triage.get("fix_effort"))}' if triage.get('fix_effort') else '',
        f'Reachability: {_fl(triage.get("reachability"))}' if triage.get('reachability') else '',
    ] if x)
    if factors:
        elems.append(Paragraph(factors, styles['frow']))

    # CWE / OWASP / Rule
    meta = '  ·  '.join(x for x in [
        f'CWE: {_safe(f.cwe)}' if f.cwe else '',
        f'OWASP: {_safe(f.owasp)}' if f.owasp else '',
        f'Rule: {_safe(f.rule_id)}' if f.rule_id else '',
    ] if x)
    if meta:
        elems.append(Paragraph(meta, styles['meta']))

    if triage.get('rationale'):
        elems.append(Spacer(1, 5))
        elems.append(_callout('Council Rationale', _safe(triage['rationale']), C_GRAY, styles))

    if f.exploit_scenario:
        elems.append(Spacer(1, 5))
        elems.append(_callout('How It Could Be Exploited', _safe(f.exploit_scenario), C_ORANGE, styles))

    if f.remediation:
        elems.append(Spacer(1, 5))
        elems.append(_callout('Remediation', _safe(f.remediation), C_GREEN, styles))

    if f.narrative:
        elems.append(Spacer(1, 5))
        elems.append(_callout('Analysis', _safe(f.narrative), C_GRAY, styles))

    if triage.get('in_chain'):
        elems.append(Spacer(1, 4))
        elems.append(Paragraph(
            'Attack chain member — priority bumped one tier',
            _ps('_ch', fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=C_PURPLE),
        ))

    if override and override.original_priority != override.override_priority:
        note = f': {_safe(override.rationale)}' if override.rationale else ''
        elems.append(Spacer(1, 4))
        elems.append(Paragraph(
            f'Analyst override: {_safe(override.original_priority)} to {_safe(override.override_priority)}{note}',
            _ps('_ov', fontName='Helvetica-Bold', fontSize=8, leading=10,
                textColor=HexColor('#713f12')),
        ))

    elems.append(Spacer(1, 10))
    return KeepTogether(elems)


# ── Cover page ────────────────────────────────────────────────────────────────

def _thin_rule(col: HexColor, thickness: float = 0.5) -> Table:
    """Single-row Table rendered as a horizontal rule (works on dark bg)."""
    t = Table([['']], colWidths=[BW])
    t.setStyle(TableStyle([
        ('LINEABOVE',     (0, 0), (-1, 0), thickness, col),
        ('TOPPADDING',    (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ('LEFTPADDING',   (0, 0), (-1, -1), 0),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
    ]))
    return t


def _cover_story(report_type: str, target: str, generated: str,
                 summary_data: list, styles: dict) -> list:
    elems: list = [Spacer(1, 3.0 * cm)]
    elems.append(_thin_rule(C_SLATE, 2))
    elems.append(Spacer(1, 0.4 * cm))
    elems.append(Paragraph('SECURITY REPORT', styles['cover_label']))
    elems.append(Spacer(1, 3))
    elems.append(Paragraph(_safe(report_type), styles['cover_type']))
    elems.append(Spacer(1, 0.5 * cm))
    elems.append(Paragraph(_safe(target), styles['cover_title']))
    elems.append(Paragraph(_safe(generated), styles['cover_meta']))
    elems.append(Spacer(1, 0.9 * cm))
    elems.append(_thin_rule(C_SLATE))
    elems.append(Spacer(1, 0.5 * cm))

    if summary_data:
        tbl = Table(summary_data, colWidths=[2.2 * cm, BW - 5.5 * cm, 2.5 * cm])
        tbl.setStyle(TableStyle([
            ('FONTNAME',      (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE',      (0, 0), (-1, -1), 10),
            ('TEXTCOLOR',     (0, 0), (-1, -1), C_GRAY),
            ('FONTNAME',      (0, 0), (0, -1), 'Helvetica-Bold'),
            ('TOPPADDING',    (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING',   (0, 0), (-1, -1), 0),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 0),
            ('LINEBELOW',     (0, 0), (-1, -2), 0.25, C_SLATE),
        ]))
        elems.append(tbl)

    return elems


# ── Public API ────────────────────────────────────────────────────────────────

def _para(text: str, style_name: str, styles: dict, **kw) -> Paragraph:
    return Paragraph(text, _ps('_p', parent=styles[style_name], **kw))


def build_scan_pdf(job, findings) -> bytes:
    """Executive-ready scan report PDF."""
    from collections import defaultdict

    buf = BytesIO()
    styles = _make_styles()
    target = job.target_name or str(job.id)
    generated = utcnow().strftime('%Y-%m-%d %H:%M UTC')

    doc = _TridentDoc(buf, 'Scan Report', target, generated)
    toc = _make_toc()
    story: list = []

    # Group by severity
    by_sev: dict[str, list] = defaultdict(list)
    for f in findings:
        by_sev[(f.severity or 'info').lower()].append(f)

    sev_counts = [(s, len(by_sev[s])) for s in SEV_ORDER if by_sev[s]]
    total = sum(c for _, c in sev_counts)

    # Cover summary table
    def _dark_bold(txt, sz=10, align=TA_RIGHT):
        return Paragraph(txt, _ps('_w', fontName='Helvetica-Bold', fontSize=sz,
                                   leading=14, textColor=C_DARK, alignment=align))

    SEV_PRINT_COLOR = {
        'critical': HexColor('#991b1b'), 'high':   HexColor('#9a3412'),
        'medium':   HexColor('#92400e'), 'low':    HexColor('#075985'),
        'info':     HexColor('#475569'),
    }
    summary = [
        [Paragraph('SEVERITY', _ps('_sh', fontName='Helvetica-Bold', fontSize=8, textColor=C_MUTED)),
         Paragraph('', styles['cover_meta']),
         Paragraph('COUNT', _ps('_sc', fontName='Helvetica-Bold', fontSize=8, textColor=C_MUTED,
                                 alignment=TA_RIGHT))],
    ]
    for sev, cnt in sev_counts:
        fg = SEV_PRINT_COLOR.get(sev, C_MUTED)
        summary.append([
            Paragraph(sev.upper(), _ps('_sv', fontName='Helvetica-Bold', fontSize=10, textColor=fg)),
            Paragraph('', styles['cover_meta']),
            _dark_bold(str(cnt)),
        ])
    summary.append([
        _dark_bold('TOTAL', align=TA_RIGHT),
        Paragraph('', styles['cover_meta']),
        _dark_bold(str(total), sz=13),
    ])

    story.extend(_cover_story('Scan Report', target, generated, summary, styles))

    # TOC page
    story.append(NextPageTemplate('Body'))
    story.append(PageBreak())
    story.append(Paragraph('Contents', styles['toc_head']))
    story.append(toc)

    # Sections
    for sev in SEV_ORDER:
        items = by_sev[sev]
        if not items:
            continue
        bg = SEV_BG.get(sev, C_SLATE)
        story.append(PageBreak())
        story.append(_section_band(
            sev.upper(), sev.capitalize(), bg,
            [f'{len(items)} finding{"s" if len(items) != 1 else ""}'],
            styles,
        ))
        story.append(Spacer(1, 10))
        for f in items:
            story.append(_scan_card(f, styles))

    doc.multiBuild(story)
    return buf.getvalue()


def build_triage_pdf(job, findings, overrides: dict) -> bytes:
    """Executive-ready triage report PDF."""
    from collections import defaultdict
    from trident.triage import PLAYBOOK, TIERS

    buf = BytesIO()
    styles = _make_styles()
    target = job.target_name or str(job.id)
    generated = utcnow().strftime('%Y-%m-%d %H:%M UTC')

    doc = _TridentDoc(buf, 'Triage Report', target, generated)
    toc = _make_toc()
    story: list = []

    # Group by tier
    by_tier: dict[str, list] = defaultdict(list)
    untriaged: list = []
    for f in findings:
        if f.priority in TIERS:
            by_tier[f.priority].append(f)
        else:
            untriaged.append(f)

    tier_counts = [(t, len(by_tier[t])) for t in TIERS if by_tier[t]]
    total = sum(c for _, c in tier_counts)

    # Cover summary — print-safe dark text
    TIER_PRINT_COLOR = {
        'P0': HexColor('#991b1b'), 'P1': HexColor('#9a3412'),
        'P2': HexColor('#92400e'), 'P3': HexColor('#075985'), 'P4': HexColor('#475569'),
    }

    def _dk(txt, sz=10, bold=False, align=TA_RIGHT):
        fn = 'Helvetica-Bold' if bold else 'Helvetica'
        return Paragraph(txt, _ps('_dk', fontName=fn, fontSize=sz,
                                   textColor=C_DARK, alignment=align))

    summary = [
        [Paragraph('TIER', _ps('_th', fontName='Helvetica-Bold', fontSize=8, textColor=C_MUTED)),
         Paragraph('SLA', _ps('_sl', fontName='Helvetica-Bold', fontSize=8, textColor=C_MUTED)),
         Paragraph('COUNT', _ps('_sc', fontName='Helvetica-Bold', fontSize=8,
                                 textColor=C_MUTED, alignment=TA_RIGHT))],
    ]
    for tier, cnt in tier_counts:
        fg = TIER_PRINT_COLOR.get(tier, C_MUTED)
        pb = PLAYBOOK[tier]
        summary.append([
            Paragraph(tier, _ps('_t', fontName='Helvetica-Bold', fontSize=10, textColor=fg)),
            Paragraph(pb['sla'], _ps('_s', fontName='Helvetica', fontSize=9, textColor=C_MUTED)),
            _dk(str(cnt), bold=True),
        ])
    summary.append([
        _dk('TOTAL', bold=True, align=TA_RIGHT),
        Paragraph('', styles['cover_meta']),
        _dk(str(total), sz=13, bold=True),
    ])

    story.extend(_cover_story('Triage Report', target, generated, summary, styles))

    # TOC page
    story.append(NextPageTemplate('Body'))
    story.append(PageBreak())
    story.append(Paragraph('Contents', styles['toc_head']))
    story.append(toc)

    # Tier sections
    for tier in TIERS:
        items = by_tier[tier]
        if not items:
            continue
        sev_key = TIER_SEV.get(tier, 'info')
        bg = SEV_BG.get(sev_key, C_SLATE)
        pb = PLAYBOOK[tier]

        story.append(PageBreak())
        story.append(_section_band(
            tier, pb['label'], bg,
            [f'SLA: {pb["sla"]}',
             pb['how'],
             f'{len(items)} finding{"s" if len(items) != 1 else ""}'],
            styles,
        ))
        story.append(Spacer(1, 10))
        for f in items:
            story.append(_triage_card(f, overrides.get(f.id), tier, styles))

    # Untriaged section
    if untriaged:
        story.append(PageBreak())
        ut_band = _section_band(
            '—', 'Confirmed — Not Yet Triaged', C_SLATE,
            [f'{len(untriaged)} finding{"s" if len(untriaged) != 1 else ""}'],
            styles,
        )
        story.append(ut_band)
        story.append(Spacer(1, 10))
        for f in untriaged:
            story.append(_scan_card(f, styles))

    doc.multiBuild(story)
    return buf.getvalue()

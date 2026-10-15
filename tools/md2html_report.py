"""Render a research report (the Markdown subset used in reports/) to one self-contained HTML page.
Handles headings, paragraphs, pipe tables, fenced code (```mermaid -> <pre class="mermaid">), ordered/unordered
lists with one nesting level, inline code, bold, italics, links, bare URLs, and local SVG images (inlined and
re-coloured to theme tokens). Usage: md2html_report.py <report.md> <template.html> <out.html>"""
import sys, re, html, os

def slug(t, seen):
    s = re.sub(r'[^a-z0-9]+', '-', re.sub(r'<[^>]+>', '', t).lower()).strip('-')[:60] or 'section'
    base, k = s, 2
    while s in seen: s = f'{base}-{k}'; k += 1
    seen.add(s); return s

def inline(t):
    codes = []
    def keep(m):
        codes.append('<code>' + html.escape(m.group(1)) + '</code>'); return f'\x00{len(codes) - 1}\x00'
    t = re.sub(r'`([^`]+)`', keep, t)
    t = html.escape(t, quote=False)
    t = re.sub(r'\[([^\]]+)\]\((https?://[^)\s]+)\)', r'<a href="\2">\1</a>', t)
    t = re.sub(r'(?<!["=>])(https?://[^\s<)]+)', r'<a href="\1">\1</a>', t)
    t = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', t)
    t = re.sub(r'(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])', r'<em>\1</em>', t)
    return re.sub(r'\x00(\d+)\x00', lambda m: codes[int(m.group(1))], t)

def cells(row):
    row = row.strip().strip('|').replace('\\|', '\x01')
    return [c.strip().replace('\x01', '|') for c in row.split('|')]

def svg_inline(path, alt="Stage 5 entropy per 1 KB block, before and after decryption"):
    s = open(path).read()
    s = re.sub(r'<svg ', f'<svg role="img" aria-label="{html.escape(alt, quote=True)}" class="fig" ', s, count=1)
    s = s.replace('<rect width="960" height="420" fill="#fff"/>', '<rect width="960" height="420" style="fill:var(--surface)"/>')
    s = s.replace('stroke="#ddd"', 'style="stroke:var(--rule)"').replace('stroke="#212121"', 'style="stroke:var(--fg)"')
    s = s.replace('stroke="#c62828"', 'style="stroke:var(--alert)"')
    s = s.replace('font-family="sans-serif" font-size="12">', 'font-family="var(--mono)" font-size="12"><style>text{fill:var(--muted)}</style>', 1)
    return s

def convert(md, base_dir):
    lines = md.split('\n'); out = []; toc = []; seen = set(); i = 0; title = ''
    meta_done = False
    while i < len(lines):
        l = lines[i]
        if not l.strip(): i += 1; continue
        m = re.match(r'^(#{1,3}) (.+)$', l)
        if m:
            lvl, txt = len(m.group(1)), m.group(2)
            if lvl == 1: title = txt; i += 1; continue
            h = inline(txt); sid = slug(h, seen)
            if lvl <= 3: toc.append((lvl, sid, re.sub(r'<[^>]+>', '', h)))
            out.append(f'<h{lvl} id="{sid}"><a class="anchor" href="#{sid}" aria-hidden="true">#</a>{h}</h{lvl}>'); i += 1; continue
        if l.startswith('```'):
            lang = l[3:].strip(); j = i + 1; buf = []
            while not lines[j].startswith('```'): buf.append(lines[j]); j += 1
            body = html.escape('\n'.join(buf))
            out.append(f'<pre class="mermaid">{body}</pre>' if lang == 'mermaid' else f'<div class="code"><pre><code>{body}</code></pre></div>')
            i = j + 1; continue
        if l.startswith('|'):
            rows = []
            while i < len(lines) and lines[i].startswith('|'): rows.append(lines[i]); i += 1
            head, body = cells(rows[0]), [cells(r) for r in rows[2:]]
            if not meta_done and all(not h for h in head):
                meta_done = True
                out.append('<dl class="meta">' + ''.join(f'<dt>{inline(k)}</dt><dd>{inline(v)}</dd>' for k, v in body) + '</dl>')
                continue
            t = '<thead><tr>' + ''.join(f'<th>{inline(h)}</th>' for h in head) + '</tr></thead><tbody>'
            t += ''.join('<tr>' + ''.join(f'<td>{inline(c)}</td>' for c in r) + '</tr>' for r in body) + '</tbody>'
            out.append(f'<div class="table-wrap"><table>{t}</table></div>'); continue
        m = re.match(r'^!\[([^\]]*)\]\(([^)]+)\)', l)
        if m:
            p = os.path.join(base_dir, m.group(2))
            out.append(f'<figure>{svg_inline(p, m.group(1) or "figure") if p.endswith(".svg") else html.escape(m.group(1))}'); i += 1
            # the following italic paragraph is the caption
            while i < len(lines) and not lines[i].strip(): i += 1
            cap = []
            while i < len(lines) and lines[i].strip(): cap.append(lines[i].strip()); i += 1
            out.append(f'<figcaption>{inline(" ".join(cap).strip("*"))}</figcaption></figure>'); continue
        if re.match(r'^(\d+\.|-) ', l):
            ordered = bool(re.match(r'^\d+\.', l)); items = []; i0 = i
            while i < len(lines) and (re.match(r'^(\d+\.|-) ', lines[i]) or (lines[i].startswith('   ') and lines[i].strip()) or (lines[i].startswith('  ') and lines[i].strip())):
                if re.match(r'^(\d+\.|-) ', lines[i]): items.append([re.sub(r'^(\d+\.|-) ', '', lines[i]), []])
                elif re.match(r'^\s+- ', lines[i]): items[-1][1].append(re.sub(r'^\s+- ', '', lines[i]))
                elif items[-1][1]: items[-1][1][-1] += ' ' + lines[i].strip()
                else: items[-1][0] += ' ' + lines[i].strip()
                i += 1
            tag = 'ol' if ordered else 'ul'
            li = ''.join(f'<li>{inline(a)}' + (('<ul>' + ''.join(f'<li>{inline(x)}</li>' for x in sub) + '</ul>') if sub else '') + '</li>' for a, sub in items)
            out.append(f'<{tag}>{li}</{tag}>'); continue
        buf = []
        while i < len(lines) and lines[i].strip() and not re.match(r'^(#{1,3} |```|\||!\[|(\d+\.|-) )', lines[i]):
            buf.append(lines[i].strip()); i += 1
        out.append(f'<p>{inline(" ".join(buf))}</p>')
    return title, '\n'.join(out), toc

if __name__ == '__main__':
    md = open(sys.argv[1]).read(); tpl = open(sys.argv[2]).read()
    title, body, toc = convert(md, os.path.dirname(os.path.abspath(sys.argv[1])))
    nav = ''.join(f'<li class="l{lvl}"><a href="#{sid}">{html.escape(html.unescape(t))}</a></li>' for lvl, sid, t in toc)
    page = tpl.replace('{{TITLE}}', inline(title)).replace('{{BODY}}', body).replace('{{TOC}}', nav)
    open(sys.argv[3], 'w').write(page)
    print('sections', len(toc), 'bytes', len(page))

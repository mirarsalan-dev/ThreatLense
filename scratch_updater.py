import glob
import os
import re

template_dir = r"c:\threatlense\app\templates"
files = glob.glob(os.path.join(template_dir, "*.html"))

for file in files:
    # Skip already updated files or base files
    if os.path.basename(file) in ["base.html", "cases.html", "autopsy.html", "command_center.html", "login.html", "register.html"]:
        continue
        
    with open(file, "r", encoding="utf-8") as f:
        content = f.read()
        
    if "<main class=\"main-workspace\">" in content or "<main class=\"main-workspace p-4\">" in content:
        # Determine a title from the filename
        name = os.path.basename(file).replace(".html", "").replace("_", " ").upper()
        
        window_html = f"""<div class="desktop-workspace">
    <div class="cyber-window" style="height: 100%;">
        <div class="cyber-window-header">
            <div>● ● ● THREATLENSE // {name}</div>
            <div class="window-controls">
                <div class="win-btn win-min"></div>
                <div class="win-btn win-max"></div>
                <div class="win-btn win-close"></div>
            </div>
        </div>
        <div class="cyber-window-body">"""
        
        content = re.sub(r'<main class="main-workspace[^>]*>', window_html, content)
        content = content.replace("</main>", "</div>\n    </div>\n</div>")
        
        with open(file, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Updated {os.path.basename(file)}")

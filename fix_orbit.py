import re

# Read the file
with open('web/templates/route.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix OrbitControls CDN - use the correct path for r128
content = content.replace(
    '<script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>',
    '<script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/jsm/controls/OrbitControls.js" type="module"></script>'
)

# But wait, module scripts won't work with the current setup. Let's use unpkg instead
content = content.replace(
    '<script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/jsm/controls/OrbitControls.js" type="module"></script>',
    '<script src="https://unpkg.com/three@0.128.0/examples/js/controls/OrbitControls.js"></script>'
)

# Write back
with open('web/templates/route.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("OrbitControls CDN path fixed!")

import re

# Read the file
with open('web/templates/route.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add OrbitControls script after THREE.js
content = content.replace(
    '<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>',
    '<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>\n    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>'
)

# 2. Add controls variable
content = content.replace(
    'let scene, camera, renderer, globe, pathLines = [], hopMarkers = [];\n        let isRotating = true;',
    'let scene, camera, renderer, globe, pathLines = [], hopMarkers = [], controls;'
)

# 3. Add bump map loading and remove bumpScale from wrong position
content = content.replace(
    '// Load realistic Earth texture from server\n            const textureLoader = new THREE.TextureLoader();\n            const earthTexture = textureLoader.load(\'/static/earth_texture.jpg\');\n\n            // Create globe material with realistic texture\n            const globeMaterial = new THREE.MeshPhongMaterial({\n                map: earthTexture,\n                specular: 0x222222,\n                shininess: 15,\n                bumpScale: 0.02\n            });',
    '// Load realistic Earth texture and bump map from server\n            const textureLoader = new THREE.TextureLoader();\n            const earthTexture = textureLoader.load(\'/static/earth_texture.jpg\');\n            const bumpTexture = textureLoader.load(\'/static/earth_bump.jpg\');\n\n            // Create globe material with realistic texture and bump map\n            const globeMaterial = new THREE.MeshPhongMaterial({\n                map: earthTexture,\n                bumpMap: bumpTexture,\n                bumpScale: 0.005,\n                specular: 0x222222,\n                shininess: 15\n            });'
)

# 4. Remove wireframe code
wireframe_pattern = r'            // Add wireframe overlay for visual effect\r?\n            const wireframeGeo = new THREE\.SphereGeometry\(1\.002, 36, 36\);\r?\n            const wireframeMat = new THREE\.MeshBasicMaterial\(\{\r?\n                color: 0x6366f1,\r?\n                wireframe: true,\r?\n                transparent: true,\r?\n                opacity: 0\.15\r?\n            \}\);\r?\n            const wireframe = new THREE\.Mesh\(wireframeGeo, wireframeMat\);\r?\n            globe\.add\(wireframe\);\r?\n\r?\n'
content = re.sub(wireframe_pattern, '', content)

# 5. Add OrbitControls before window.addEventListener
content = content.replace(
    '            scene.add(light2);\r\n\r\n            window.addEventListener(\'resize\', () => {',
    '            scene.add(light2);\r\n\r\n            // Add OrbitControls for mouse interaction\r\n            controls = new THREE.OrbitControls(camera, renderer.domElement);\r\n            controls.enableDamping = true;\r\n            controls.dampingFactor = 0.05;\r\n            controls.minDistance = 1.5;\r\n            controls.maxDistance = 5;\r\n            controls.enablePan = false;\r\n            controls.autoRotate = false;\r\n\r\n            window.addEventListener(\'resize\', () => {'
)

# 6. Remove auto rotation from animate function
content = content.replace(
    '        function animate() {\r\n            requestAnimationFrame(animate);\r\n            if (isRotating && globe) globe.rotation.y += 0.002;\r\n            renderer.render(scene, camera);\r\n        }',
    '        function animate() {\r\n            requestAnimationFrame(animate);\r\n            controls.update();\r\n            renderer.render(scene, camera);\r\n        }'
)

# Write back
with open('web/templates/route.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("File updated successfully!")

import subprocess
import shutil
import os

# -----------------------------
# Paths
# -----------------------------
project_root = os.path.abspath(".")
assets_folder = os.path.join(project_root, "assets")
dist_folder = os.path.join(project_root, "dist")
build_folder = os.path.join(project_root, "build")
osav_script = os.path.join(project_root, "osav.py")
osav_icon = os.path.join(assets_folder, "osav.ico")
iss_template = os.path.join(project_root, "setup.iss")
iss_file = os.path.join(project_root, "OSAV_Setup.iss")  # Will be generated

# Inno Setup Compiler path
isscc_path = r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not os.path.isfile(isscc_path):
    raise FileNotFoundError(f"Inno Setup compiler not found at {isscc_path}")

# -----------------------------
# 1. Build exe with PyInstaller
# -----------------------------
pyinstaller_cmd = [
    "python", "-m", "PyInstaller",
    "--clean",
    "--onefile",
    "--windowed",
    f"--icon={osav_icon}",
    f"--add-data={osav_icon};assets",
    osav_script
]

print("Building osav.exe with PyInstaller...")
subprocess.run(pyinstaller_cmd, check=True)

# Move exe to build\osav
exe_source = os.path.join(dist_folder, "osav.exe")
exe_dest_folder = os.path.join(build_folder, "osav")
os.makedirs(exe_dest_folder, exist_ok=True)
exe_dest = os.path.join(exe_dest_folder, "osav.exe")
shutil.move(exe_source, exe_dest)

# -----------------------------
# 2. Generate ISS with correct SourcePath
# -----------------------------
with open(iss_template, "r", encoding="utf-8") as f:
    content = f.read()

content = content.replace("{SOURCE_PATH}", exe_dest_folder.replace("\\", "\\\\"))

with open(iss_file, "w", encoding="utf-8") as f:
    f.write(content)

print(f"Generated ISS file at {iss_file}")

# -----------------------------
# 3. Run Inno Setup to create installer
# -----------------------------
print("Building installer with Inno Setup...")
subprocess.run([isscc_path, iss_file], check=True)

print("Build complete! Installer should be in Output folder.")

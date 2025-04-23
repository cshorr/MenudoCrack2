

import subprocess

hashcat_exe = r"P:\Hacking.Py_Hashcat\hashcat-6.2.6\hashcat.exe"
result = subprocess.run([hashcat_exe, "--help"], capture_output=True, text=True)

print("STDOUT:\n", result.stdout)
print("STDERR:\n", result.stderr)

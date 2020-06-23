# mf_inspector
Tool for mass inspecting files

# Requirements
```shell
pip3 install -r requirements.txt
```

# Running
```shell
python3 ./walker.py -d test_folder/
```

## Example output
```csv
path,SHA-256,file type,detail,metadata
test_folder/2Fs11235-017-0334-z.pdf,4774a4ca47f89bb28cf5c19cf94c8b7868137a1d2cac27802ff385a25e566b24,application/pdf,"Contains OpenAction, AcroForm, (2 instances in total)","Author=B. B. Gupta; Title=Defending against phishing attacks: taxonomy of methods, current issues and future directions; Creator=Springer"
test_folder/6point6 Culture and Values - Preview.pdf,c2ee1479cb8cfb07cc9969cd9b2181f320248ab5434eff27b8f6975c7705dffe,application/pdf,Contains no dangerous artefacts,Author=None; Title=None; Creator=None
test_folder/bad.pdf,1aa5f45734e6200f21fa96dddd2df55f353d22e42c3b1d6653c0ddbfd5a76054,application/pdf,"Contains JavaScript, OpenAction, EmbeddedFile, (5 instances in total)",Author=None; Title=None; Creator=None
test_folder/bgrep,e13d65c0f1c5a37d1f5d854795ccdfec18c0b8de18a4b33a5df42a5197863071,application/x-executable,ELF,
test_folder/cav-linux_x64.deb,325b819b041a7b27026ba85f66ea808d0d11ad39d94bc13ae6d95802413495b6,application/vnd.debian.binary-package,,
test_folder/HMCTS TVM LLD v. 0.5 (1).docx,2e9418e03f9cbe0dcdb6fd2120131039e028c024640458afeb6bf1319927aaa9,application/vnd.openxmlformats-officedocument.wordprocessingml.document,office XML doc,
test_folder/SIX.SIX.149 A4 Template CYBER V1.docx,af81b5c2123ac4d3784117bb92705d0f4c1af014e9f095b85f5b6dcbb9db2b5a,application/vnd.openxmlformats-officedocument.wordprocessingml.document,office XML doc,
test_folder/Vysor-win32-ia32.exe.file,37cc5bf5e50c164ec9aca4d9129dcca7c3002ee7b5cf4339acd29353758023b4,application/x-dosexec,PE,
test_folder/whiptail,2c5a08daacd6f7dc046397ccd68c2b92f5678d8e93218b55c8014cfe1aec5d7c,application/x-sharedlib,ELF,
test_folder/zegrep,da2da96324108bbe297a75e8ebfcb2400959bffcdaa4c88b797c4d0ce0c94c50,text/x-shellscript,,
```

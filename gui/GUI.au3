#include <ButtonConstants.au3>
#include <ComboConstants.au3>
#include <EditConstants.au3>
#include <GUIConstantsEx.au3>
#include <StaticConstants.au3>
#include <TabConstants.au3>
#include <WindowsConstants.au3>
#Region ### START Koda GUI section ### Form=h:\prgm\programim\autoit-v3\scite\koda\forms\prot1.kxf
$Form1_1 = GUICreate("AUTO Toolkit GUI - Copyright © 2020-2022 ALBANESE Research Lab ", 710, 497, 191, 122)
$Tab1 = GUICtrlCreateTab(16, 8, 681, 473)
$TabSheet1 = GUICtrlCreateTabItem("Diffie-Hellman")
$Label2 = GUICtrlCreateLabel("Elliptic Curve:", 448, 48, 68, 17)
$Button1 = GUICtrlCreateButton("Generate Keypair", 40, 48, 99, 25)
$Button2 = GUICtrlCreateButton("Derive Shared Secret", 144, 48, 121, 25)
$Combo1 = GUICtrlCreateCombo("ECDSA (Secp256r1)", 536, 48, 145, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "Brainpool160t1|Brainpool192t1|Brainpool256r1|Brainpool256t1|Brainpool512r1|Brainpool512t1|Fp256BN|Fp512BN|ANSSI FRP256v1|GOST R 34.10-2001_A|GOST R 34.10-2001_B|GOST R 34.10-2001_C|GOST R 34.10-2012_A|GOST R 34.10-2012_B|Koblitz (Secp160k1)|Koblitz (Secp192k1)|Koblitz (Secp256k1)|NUMSP256d1|NUMSP512d1|Oakley 192-bit|Oakley 256-bit|ANSI x9.62 Prime192v1|ANSI x9.62 Prime192v2|ANSI x9.62 Prime192v3|SEC2v1 Secp160r1|SEC2v1 Secp160r2|SM2|SM9|X25519")
$Button3 = GUICtrlCreateButton("Copy", 600, 112, 73, 25)
$Button4 = GUICtrlCreateButton("Copy", 600, 192, 73, 25)
$Button5 = GUICtrlCreateButton("Paste", 600, 304, 73, 25)
$Button6 = GUICtrlCreateButton("Copy", 600, 416, 73, 25)
$Label4 = GUICtrlCreateLabel("Private Key:", 40, 88, 61, 17)
$Edit1 = GUICtrlCreateEdit("", 40, 112, 537, 41, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Label5 = GUICtrlCreateLabel("Public Key:", 40, 168, 57, 17)
$Edit2 = GUICtrlCreateEdit("", 40, 192, 537, 73, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Label6 = GUICtrlCreateLabel("Shared Secret:", 40, 392, 75, 17)
$Edit3 = GUICtrlCreateEdit("", 40, 304, 537, 73, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Label7 = GUICtrlCreateLabel("Remote's side Public Key:", 40, 280, 126, 17)
$Edit4 = GUICtrlCreateEdit("", 40, 416, 537, 41, BitOR($ES_AUTOHSCROLL,$ES_READONLY,$ES_WANTRETURN,$WS_HSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$TabSheet2 = GUICtrlCreateTabItem("Digital Signature")
$Button7 = GUICtrlCreateButton("Generate Keypair", 40, 48, 99, 25)
$Button8 = GUICtrlCreateButton("Sign", 144, 48, 73, 25)
$Button12 = GUICtrlCreateButton("Verify", 224, 48, 75, 25)
$Combo2 = GUICtrlCreateCombo("ECDSA (Secp256r1)", 536, 48, 145, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "Brainpool160t1|Brainpool192t1|Brainpool256r1|Brainpool256t1|Brainpool512r1|Brainpool512t1|Ed25519|Fp256BN|Fp512BN|ANSSI FRP256v1|GOST R 34.10-2001_A|GOST R 34.10-2001_B|GOST R 34.10-2001_C|GOST R 34.10-2012_A|GOST R 34.10-2012_B|Koblitz (Secp160k1)|Koblitz (Secp192k1)|Koblitz (Secp256k1)|NUMSP256d1|NUMSP512d1|Oakley 192-bit|Oakley 256-bit|ANSI x9.62 Prime192v1|ANSI x9.62 Prime192v2|ANSI x9.62 Prime192v3|SEC2v1 Secp160r1|SEC2v1 Secp160r2|SM2|SM9")
$Combo3 = GUICtrlCreateCombo("SHA256", 536, 72, 145, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "SHA512_256|SHA512|SHA3_256|SHA3_512|Skein256|Skein512_256|Skein512|SM3|Streebog256|Streebog512|BLAKE2b256|BLAKE2b512|BLAKE2s256|GOST94-CryptoPro|Groestl|JH|Keccak256|Keccak512|LSH256|LSH512_256|LSH512|RIPEMD128|RIPEMD160|RIPEMD256|Tiger|Whirlpool")
$Button9 = GUICtrlCreateButton("Copy", 600, 112, 73, 25)
$Button10 = GUICtrlCreateButton("Paste", 600, 224, 73, 25)
$Button11 = GUICtrlCreateButton("Browse", 600, 280, 75, 25)
$Button14 = GUICtrlCreateButton("Copy", 600, 384, 73, 25)
$Button13 = GUICtrlCreateButton("Paste", 600, 416, 73, 25)
$Edit5 = GUICtrlCreateEdit("", 40, 112, 537, 41, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit6 = GUICtrlCreateEdit("", 40, 192, 537, 73, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Radio1 = GUICtrlCreateRadio("File", 48, 280, 41, 25)
GUICtrlSetState(-1, $GUI_CHECKED)
$Radio2 = GUICtrlCreateRadio("String", 48, 304, 49, 33)
$Input1 = GUICtrlCreateInput("Input File...", 112, 280, 465, 23)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit7 = GUICtrlCreateEdit("", 112, 312, 465, 41, BitOR($ES_AUTOHSCROLL,$ES_WANTRETURN,$WS_HSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit8 = GUICtrlCreateEdit("", 40, 384, 537, 73, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Label9 = GUICtrlCreateLabel("Public Key:", 40, 168, 57, 17)
$Label1 = GUICtrlCreateLabel("Elliptic Curve:", 448, 48, 68, 17)
$Label8 = GUICtrlCreateLabel("Private Key:", 40, 88, 61, 17)
$Label10 = GUICtrlCreateLabel("Signature:", 40, 360, 52, 17)
$Label11 = GUICtrlCreateLabel("Message Digest:", 448, 72, 83, 17)
$Button38 = GUICtrlCreateButton("Copy", 600, 192, 75, 25)
$TabSheet3 = GUICtrlCreateTabItem("Asymmetric")
$Button15 = GUICtrlCreateButton("Generate Keypair", 40, 48, 99, 25)
$Button18 = GUICtrlCreateButton("Encrypt", 144, 48, 75, 25)
$Button19 = GUICtrlCreateButton("Decrypt", 224, 48, 75, 25)
$Combo4 = GUICtrlCreateCombo("ECDSA (Secp256r1)", 536, 48, 145, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "Brainpool160t1|Brainpool192t1|Brainpool256t1|Brainpool512t1|Fp256BN|Fp512BN|ANSSI FRP256v1|GOST R 34.10-2001_A|GOST R 34.10-2001_B|GOST R 34.10-2001_C|GOST R 34.10-2012_A|GOST R 34.10-2012_B|Koblitz (Secp160k1)|Koblitz (Secp192k1)|Koblitz (Secp256k1)|NUMSP512d1|Oakley 192-bit|Oakley 256-bit|ANSI x9.62 Prime192v1|ANSI x9.62 Prime192v2|ANSI x9.62 Prime192v3|SEC2v1 Secp160r1|SEC2v1 Secp160r2|SM2|SM9")
$Button16 = GUICtrlCreateButton("Copy", 600, 112, 73, 25)
$Button17 = GUICtrlCreateButton("Copy", 600, 192, 73, 25)
$Button21 = GUICtrlCreateButton("Paste", 600, 224, 73, 25)
$Button20 = GUICtrlCreateButton("Copy", 600, 280, 73, 25)
$Button22 = GUICtrlCreateButton("Paste", 600, 312, 73, 25)
$Edit9 = GUICtrlCreateEdit("", 40, 112, 537, 41, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit10 = GUICtrlCreateEdit("", 40, 192, 537, 73, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit11 = GUICtrlCreateEdit("", 104, 280, 473, 57, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Label12 = GUICtrlCreateLabel("Elliptic Curve:", 448, 48, 68, 17)
$Label13 = GUICtrlCreateLabel("Private Key:", 40, 88, 61, 17)
$Label14 = GUICtrlCreateLabel("Public Key:", 40, 168, 57, 17)
$Edit26 = GUICtrlCreateEdit("", 104, 352, 473, 105, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Button55 = GUICtrlCreateButton("Paste", 600, 384, 73, 25)
$Button56 = GUICtrlCreateButton("Copy", 600, 352, 73, 25)
$Label35 = GUICtrlCreateLabel("Plaintext:", 40, 288, 47, 17)
$Label36 = GUICtrlCreateLabel("Ciphertext:", 40, 360, 54, 17)
$TabSheet4 = GUICtrlCreateTabItem("Symmetric")
$Button28 = GUICtrlCreateButton("Encrypt", 40, 48, 73, 25)
$Button29 = GUICtrlCreateButton("Decrypt", 120, 48, 75, 25)
$Combo12 = GUICtrlCreateCombo("CTR", 368, 48, 65, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "CFB8|OFB")
$iBulk = GUICtrlCreateCombo("AES (Rijndael)", 536, 48, 145, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "Anubis|ARIA|Ascon 1.2|Camellia|Chacha20Poly1305|GOST89-CryptoPro|Grain128a|HC128 (no AEAD)|HC256 (no AEAD)|HIGHT|Kuznechik|LEA|Magma|MISTY1|PRESENT|Rabbit (no AEAD)|SEED|Serpent|Simon128|Speck128|Simon64|Speck64|Snow3G (no AEAD)|SM4|Trivium (no AEAD)|TWINE|Twofish|Threefish (no AEAD)|ZUC-128 (no AEAD)|ZUC-256 (no AEAD)")
$Combo8 = GUICtrlCreateCombo("GCM", 536, 72, 145, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "MGM|CCM|EAX|OCB|SIV|SIV-PMAC")
$Button27 = GUICtrlCreateButton("Generate", 600, 104, 75, 25)
$Button49 = GUICtrlCreateButton("Generate", 600, 136, 75, 25)
$Button26 = GUICtrlCreateButton("Copy", 600, 200, 73, 25)
$Button24 = GUICtrlCreateButton("Copy", 600, 296, 73, 25)
$Button23 = GUICtrlCreateButton("Paste", 600, 328, 73, 25)
$Button25 = GUICtrlCreateButton("Browse", 600, 400, 75, 25)
$Button30 = GUICtrlCreateButton("Browse", 600, 432, 75, 25)
$Edit12 = GUICtrlCreateEdit("", 104, 104, 473, 25, $ES_WANTRETURN)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit25 = GUICtrlCreateEdit("", 104, 136, 473, 25, $ES_WANTRETURN)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Input4 = GUICtrlCreateInput("Additional_Authenticated_Data", 240, 168, 265, 23)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Checkbox1 = GUICtrlCreateCheckbox("AEAD", 520, 168, 49, 25)
$Radio4 = GUICtrlCreateRadio("String", 40, 200, 49, 25)
GUICtrlSetState(-1, $GUI_CHECKED)
$Radio3 = GUICtrlCreateRadio("File", 40, 400, 41, 25)
$Edit14 = GUICtrlCreateEdit("", 104, 200, 473, 57, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
GUICtrlSetTip(-1, "Plaintext of 156 characters")
$Checkbox4 = GUICtrlCreateCheckbox("Base64", 520, 264, 57, 25)
$Edit15 = GUICtrlCreateEdit("", 104, 296, 473, 89, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Input2 = GUICtrlCreateInput("Input...", 104, 400, 473, 23)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Input3 = GUICtrlCreateInput("Output...", 104, 432, 473, 23)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Label = GUICtrlCreateLabel("Bulk Cipher:", 448, 48, 61, 17)
$Label3 = GUICtrlCreateLabel("Key:", 40, 112, 25, 17)
$Label15 = GUICtrlCreateLabel("Plaintext:", 104, 176, 47, 17)
$Label16 = GUICtrlCreateLabel("Ciphertext:", 104, 272, 54, 17)
$Label21 = GUICtrlCreateLabel("AEAD Mode:", 448, 72, 66, 17)
$Label33 = GUICtrlCreateLabel("Nonce/IV:", 40, 144, 54, 17)
$Label34 = GUICtrlCreateLabel("Mode of Operation:", 264, 48, 95, 17)
$TabSheet5 = GUICtrlCreateTabItem("Hash Digest")
$Button34 = GUICtrlCreateButton("Hash", 40, 48, 75, 25)
$Button35 = GUICtrlCreateButton("Check", 120, 48, 73, 25)
$Button39 = GUICtrlCreateButton("Symmetric Key Derivation", 200, 48, 145, 25)
$Combo5 = GUICtrlCreateCombo("SHA256", 536, 48, 145, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "SHA512_256|SHA512|SHA3_256|SHA3_512|CubeHash|Skein256|Skein512_256|Skein512|SM3|Streebog256|Streebog512|BLAKE2b256|BLAKE2b512|BLAKE2s128|BLAKE2s256|GOST94-CryptoPro|Groestl|JH|Keccak256|Keccak512|LSH256|LSH512_256|LSH512|RIPEMD128|RIPEMD160|RIPEMD256|Tiger|Whirlpool")
$Button31 = GUICtrlCreateButton("Browse", 600, 88, 75, 25)
$Button32 = GUICtrlCreateButton("Copy", 600, 192, 73, 25)
$Button33 = GUICtrlCreateButton("Paste", 600, 224, 73, 25)
$Button36 = GUICtrlCreateButton("Generate", 600, 288, 75, 25)
$Button37 = GUICtrlCreateButton("Copy", 600, 400, 73, 25)
$Combo6 = GUICtrlCreateCombo("512", 600, 432, 73, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "256|192|128|96|80|64|40|32")
$Radio5 = GUICtrlCreateRadio("File", 48, 88, 41, 25)
GUICtrlSetState(-1, $GUI_CHECKED)
$Radio6 = GUICtrlCreateRadio("String", 48, 112, 49, 33)
$Input5 = GUICtrlCreateInput("Input File...", 112, 88, 465, 23)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit17 = GUICtrlCreateEdit("", 112, 120, 465, 41, BitOR($ES_AUTOHSCROLL,$ES_WANTRETURN,$WS_HSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit16 = GUICtrlCreateEdit("", 40, 192, 537, 57, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Checkbox2 = GUICtrlCreateCheckbox("HMAC", 520, 256, 57, 25)
$Edit18 = GUICtrlCreateEdit("", 40, 288, 537, 41, BitOR($ES_AUTOHSCROLL,$ES_WANTRETURN,$WS_HSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Input6 = GUICtrlCreateInput("Salt", 40, 368, 201, 23)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Input7 = GUICtrlCreateInput("Additional_Info", 248, 368, 193, 23)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Input8 = GUICtrlCreateInput("Iter", 448, 368, 65, 23, BitOR($GUI_SS_DEFAULT_INPUT,$ES_NUMBER))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Checkbox3 = GUICtrlCreateCheckbox("PBKDF2", 520, 368, 57, 25)
$Edit19 = GUICtrlCreateEdit("", 40, 400, 537, 57, BitOR($ES_AUTOVSCROLL,$ES_READONLY,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Label17 = GUICtrlCreateLabel("Digest:", 40, 168, 37, 17)
$Label18 = GUICtrlCreateLabel("Message Digest:", 448, 48, 83, 17)
$Label19 = GUICtrlCreateLabel("Secret:", 40, 264, 38, 17)
$Label20 = GUICtrlCreateLabel("KDF:", 40, 344, 28, 17)
$TabSheet6 = GUICtrlCreateTabItem("TCP/IP")
$Button40 = GUICtrlCreateButton("Send", 40, 48, 75, 25)
$Button41 = GUICtrlCreateButton("Dump", 120, 48, 73, 25)
$Button42 = GUICtrlCreateButton("Get IP", 200, 48, 73, 25)
$Combo7 = GUICtrlCreateCombo("ECDSA", 536, 48, 145, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "Ed25519|GOST2012|SM2")
$Button43 = GUICtrlCreateButton("Copy", 600, 112, 75, 25)
$Button44 = GUICtrlCreateButton("Paste", 600, 144, 75, 25)
$Button45 = GUICtrlCreateButton("Copy", 600, 304, 75, 25)
$Button46 = GUICtrlCreateButton("Paste", 600, 336, 75, 25)
$Input9 = GUICtrlCreateInput("127.0.0.1", 416, 80, 105, 21)
$Input10 = GUICtrlCreateInput("8081", 528, 80, 49, 21)
$Edit20 = GUICtrlCreateEdit("", 48, 112, 529, 145, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
$Input11 = GUICtrlCreateInput("127.0.0.1", 416, 272, 105, 21)
$Input12 = GUICtrlCreateInput("8081", 528, 272, 49, 21)
$Edit21 = GUICtrlCreateEdit("", 48, 304, 529, 153, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
$Label22 = GUICtrlCreateLabel("IP/Port:", 368, 272, 41, 17)
$Label23 = GUICtrlCreateLabel("Algorithm:", 480, 48, 50, 17)
$Label24 = GUICtrlCreateLabel("IP/Port", 368, 80, 38, 17)
$Label25 = GUICtrlCreateLabel("Listen:", 48, 88, 35, 17)
$Label26 = GUICtrlCreateLabel("Dial:", 48, 280, 25, 17)
$TabSheet7 = GUICtrlCreateTabItem("OMAC1/MAC")
$Button47 = GUICtrlCreateButton("Sign", 40, 48, 75, 25)
$Button48 = GUICtrlCreateButton("Check", 120, 48, 73, 25)
$Combo10 = GUICtrlCreateCombo("MAC", 368, 48, 65, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "CMAC|PMAC")
$Combo9 = GUICtrlCreateCombo("Chaskey", 536, 48, 145, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "Poly1305|SipHash64|SipHash128|GOST-MAC 32-bit|GOST-MAC 64-bit|Snow3G|ZUC-128|ZUC-256 32-bit|ZUC-256 64-bit|ZUC-256 128-bit")
$Combo11 = GUICtrlCreateCombo("AES (Rijndael)", 536, 72, 145, 25, BitOR($CBS_DROPDOWN,$CBS_AUTOHSCROLL))
GUICtrlSetData(-1, "Anubis|ARIA|Camellia|GOST89-CryptoPro|HIGHT|Kuznechik|LEA|Magma|MISTY1|PRESENT|SEED|Serpent|Simon128|Speck128|Simon64|Speck64|SM4|Twofish|TWINE")
$Button50 = GUICtrlCreateButton("Browse", 600, 104, 75, 25)
$Button51 = GUICtrlCreateButton("Generate", 600, 272, 75, 25)
$Button54 = GUICtrlCreateButton("Generate", 600, 336, 75, 25)
$Button52 = GUICtrlCreateButton("Copy", 600, 400, 73, 25)
$Button53 = GUICtrlCreateButton("Paste", 600, 432, 73, 25)
$Radio7 = GUICtrlCreateRadio("File", 48, 104, 41, 25)
GUICtrlSetState(-1, $GUI_CHECKED)
$Radio8 = GUICtrlCreateRadio("String", 48, 128, 49, 33)
$Input13 = GUICtrlCreateInput("Input File...", 112, 104, 465, 23)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit13 = GUICtrlCreateEdit("", 112, 136, 465, 97, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit22 = GUICtrlCreateEdit("", 40, 272, 537, 25, $ES_WANTRETURN)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit24 = GUICtrlCreateEdit("", 40, 336, 537, 25, $ES_WANTRETURN)
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Edit23 = GUICtrlCreateEdit("", 40, 400, 537, 57, BitOR($ES_AUTOVSCROLL,$ES_WANTRETURN,$WS_VSCROLL))
GUICtrlSetFont(-1, 10, 400, 0, "Consolas")
$Label27 = GUICtrlCreateLabel("MAC Algorithm:", 448, 48, 76, 17)
$Label28 = GUICtrlCreateLabel("Secret:", 40, 248, 38, 17)
$Label29 = GUICtrlCreateLabel("IV:", 40, 312, 17, 17)
$Label30 = GUICtrlCreateLabel("Digest:", 40, 376, 37, 17)
$Label31 = GUICtrlCreateLabel("Mode of Operation:", 264, 48, 95, 17)
$Label32 = GUICtrlCreateLabel("Block Cipher:", 448, 72, 67, 17)
GUICtrlCreateTabItem("")
GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###
; #INDEX# =======================================================================================================================
; Title .........: AUTO Toolkit Graphical User Interface
; AutoIt Version : 3.3.14.5
; Language ......: English
; Description ...: Handler/Wrapper for ROOTTk Golang Tool Functions.
; Author(s) .....: Pedro F. Albanese <pedroalbanese@hotmail.com>
; ===============================================================================================================================
#NoTrayIcon
#include <GUI.au3>
#include <MsgBoxConstants.au3>

Main()

Func Main()
	While 1
		$nMsg = GUIGetMsg()
		Switch $nMsg
			Case $GUI_EVENT_CLOSE
				Exit

			Case $Button1 ; Generate Keypair (DH)
				Global $sRead = GUICtrlRead($Edit1)
				Global $rRead = GUICtrlRead($Edit2)
				Switch GUICtrlRead($Combo1)
					Case "ECDSA (Secp256r1)"
						$iAlgorithm = "ecdsa"
					Case "Brainpool256r1"
						$iAlgorithm = "brainpool256r1"
					Case "Brainpool256t1"
						$iAlgorithm = "brainpool256t1"
					Case "Brainpool512r1"
						$iAlgorithm = "brainpool512r1"
					Case "Brainpool512t1"
						$iAlgorithm = "brainpool512t1"
					Case "Brainpool160t1"
						$iAlgorithm = "brainpool160t1"
					Case "Brainpool192t1"
						$iAlgorithm = "brainpool192t1"
					Case "X25519"
						$iAlgorithm = "x25519"
					Case "SM2"
						$iAlgorithm = "sm2p256v1"
					Case "SM9"
						$iAlgorithm = "sm9p256v1"
					Case "GOST R 34.10-2012_A"
						$iAlgorithm = "ecgost2012A"
					Case "GOST R 34.10-2012_B"
						$iAlgorithm = "ecgost2012B"
					Case "GOST R 34.10-2001_A"
						$iAlgorithm = "ecgost2001A"
					Case "GOST R 34.10-2001_B"
						$iAlgorithm = "ecgost2001B"
					Case "GOST R 34.10-2001_C"
						$iAlgorithm = "ecgost2001C"
					Case "Fp256BN"
						$iAlgorithm = "fp256bn"
					Case "Fp512BN"
						$iAlgorithm = "fp512bn"
					Case "ANSSI FRP256v1"
						$iAlgorithm = "frp256v1"
					Case "Secp160k1"
						$iAlgorithm = "secp160k1"
					Case "Secp192k1"
						$iAlgorithm = "secp192k1"
					Case "Secp256k1"
						$iAlgorithm = "secp256k1"
					Case "NUMSP256d1"
						$iAlgorithm = "numsp256d1"
					Case "NUMSP512d1"
						$iAlgorithm = "numsp512d1"
					Case "Oakley 192-bit"
						$iAlgorithm = "oakley192"
					Case "Oakley 256-bit"
						$iAlgorithm = "oakley256"
					Case "ANSI x9.62 Prime192v1"
						$iAlgorithm = "prime192v1"
					Case "ANSI x9.62 Prime192v2"
						$iAlgorithm = "prime192v2"
					Case "ANSI x9.62 Prime192v3"
						$iAlgorithm = "prime192v3"
					Case "SEC2v1 Secp160r1"
						$iAlgorithm = "secp160r1"
					Case "SEC2v1 Secp160r2"
						$iAlgorithm = "secp160r2"
				EndSwitch
				If $sRead = "" and $rRead = "" Then
					$CMD = "roottk -keygen -info Keypair -algorithm " & $iAlgorithm & " | roottk -util unix2dos > " & @TempDir & "keypair.txt"
				ElseIf $sRead not = "" and $rRead = "" Then
					$CMD = "roottk -keygen -info Keypair -algorithm " & $iAlgorithm & " -key """ & $sRead  & """ | roottk -util unix2dos > " & @TempDir & "keypair.txt"
				Else
					$CMD = "roottk -keygen -info Keypair -algorithm " & $iAlgorithm & " | roottk -util unix2dos > " & @TempDir & "keypair.txt"
				EndIf
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$PrivateKey = IniRead(@TempDir & "keypair.txt", "Keypair", "Private", "Not found.")
				$PublicKey = IniRead(@TempDir & "keypair.txt", "Keypair", "Public", "Not found.")
				GUICtrlSetData($Edit1, $PrivateKey)
				GUICtrlSetData($Edit2, $PublicKey)
;				FileDelete(@TempDir & "keypair.txt")
				$CMD = "roottk -shred " & @TempDir & "keypair.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button2
				Switch GUICtrlRead($Combo1)
					Case "ECDSA (Secp256r1)"
						$iAlgorithm = "ecdsa"
					Case "Brainpool256r1"
						$iAlgorithm = "brainpool256r1"
					Case "Brainpool256t1"
						$iAlgorithm = "brainpool256t1"
					Case "Brainpool512r1"
						$iAlgorithm = "brainpool512r1"
					Case "Brainpool512t1"
						$iAlgorithm = "brainpool512t1"
					Case "Brainpool160t1"
						$iAlgorithm = "brainpool160t1"
					Case "Brainpool192t1"
						$iAlgorithm = "brainpool192t1"
					Case "X25519"
						$iAlgorithm = "x25519"
					Case "SM2"
						$iAlgorithm = "sm2p256v1"
					Case "SM9"
						$iAlgorithm = "sm9p256v1"
					Case "GOST R 34.10-2012_A"
						$iAlgorithm = "ecgost2012A"
					Case "GOST R 34.10-2012_B"
						$iAlgorithm = "ecgost2012B"
					Case "GOST R 34.10-2001_A"
						$iAlgorithm = "ecgost2001A"
					Case "GOST R 34.10-2001_B"
						$iAlgorithm = "ecgost2001B"
					Case "GOST R 34.10-2001_C"
						$iAlgorithm = "ecgost2001C"
					Case "Fp256BN"
						$iAlgorithm = "fp256bn"
					Case "Fp512BN"
						$iAlgorithm = "fp512bn"
					Case "ANSSI FRP256v1"
						$iAlgorithm = "frp256v1"
					Case "Koblitz (Secp160k1)"
						$iAlgorithm = "secp160k1"
					Case "Koblitz (Secp192k1)"
						$iAlgorithm = "secp1921"
					Case "Koblitz (Secp256k1)"
						$iAlgorithm = "secp256k1"
					Case "NUMSP256d1"
						$iAlgorithm = "numsp256d1"
					Case "NUMSP512d1"
						$iAlgorithm = "numsp512d1"
					Case "Oakley 192-bit"
						$iAlgorithm = "oakley192"
					Case "Oakley 256-bit"
						$iAlgorithm = "oakley256"
					Case "ANSI x9.62 Prime192v1"
						$iAlgorithm = "prime192v1"
					Case "ANSI x9.62 Prime192v2"
						$iAlgorithm = "prime192v2"
					Case "ANSI x9.62 Prime192v3"
						$iAlgorithm = "prime192v3"
					Case "SEC2v1 Secp160r1"
						$iAlgorithm = "secp160r1"
					Case "SEC2v1 Secp160r2"
						$iAlgorithm = "secp160r2"
				EndSwitch
				Global $sRead = GUICtrlRead($Edit1)
				Global $xRead = GUICtrlRead($Edit3)
				$CMD = "echo [Keypair] > " & @TempDir & "keypair.txt & roottk -pkeyutl derive -algorithm " & $iAlgorithm  & " -key " & $sRead & " -pub " & $xRead & " | roottk -util unix2dos >> " & @TempDir & "keypair.txt"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$SharedSecret = IniRead(@TempDir & "keypair.txt", "Keypair", "Shared", "Error.")
				GUICtrlSetData($Edit4, $SharedSecret)
;				FileDelete(@TempDir & "keypair.txt")
				$CMD = "roottk -shred " & @TempDir & "keypair.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button3
				ClipPut(GUICtrlRead($Edit1))

			Case $Button4
				ClipPut(GUICtrlRead($Edit2))

			Case $Button5
				Local $sData = ClipGet()
				GUICtrlSetData($Edit3, $sData)

			Case $Button6
				ClipPut(GUICtrlRead($Edit4))

			Case $Button7 ; Generate Keypair (Signature)
				Global $sRead = GUICtrlRead($Edit5)
				Global $rRead = GUICtrlRead($Edit6)
				Switch GUICtrlRead($Combo2)
					Case "ECDSA (Secp256r1)"
						$idCurve = "ECDSA"
						$iAlgorithm = "ecdsa"
					Case "Brainpool256r1"
						$idCurve = "BRAINPOOL256R1"
						$iAlgorithm = "brainpool256r1"
					Case "Brainpool256t1"
						$idCurve = "BRAINPOOL256T1"
						$iAlgorithm = "brainpool256t1"
					Case "Brainpool512r1"
						$idCurve = "BRAINPOOL512R1"
						$iAlgorithm = "brainpool512r1"
					Case "Brainpool512t1"
						$idCurve = "BRAINPOOL512T1"
						$iAlgorithm = "brainpool512t1"
					Case "Brainpool160t1"
						$idCurve = "BRAINPOOL160T1"
						$iAlgorithm = "brainpool160t1"
					Case "Brainpool192t1"
						$idCurve = "BRAINPOOL192T1"
						$iAlgorithm = "brainpool192t1"
					Case "ED25519"
						$idCurve = "ED25519"
						$iAlgorithm = "ed25519"
					Case "SM2"
						$idCurve = "SM2P256V1"
						$iAlgorithm = "sm2p256v1"
					Case "SM9"
						$idCurve = "SM9P256V1"
						$iAlgorithm = "sm9p256v1"
					Case "GOST R 34.10-2012_A"
						$idCurve = "ECGOST2012A"
						$iAlgorithm = "ecgost2012A"
					Case "GOST R 34.10-2012_B"
						$idCurve = "ECGOST2012B"
						$iAlgorithm = "ecgost2012B"
					Case "GOST R 34.10-2001_A"
						$idCurve = "ECGOST2001A"
						$iAlgorithm = "ecgost2001A"
					Case "GOST R 34.10-2001_B"
						$idCurve = "ECGOST2001B"
						$iAlgorithm = "ecgost2001B"
					Case "GOST R 34.10-2001_C"
						$idCurve = "ECGOST2001C"
						$iAlgorithm = "ecgost2001C"
					Case "Fp256BN"
						$idCurve = "FP256BN"
						$iAlgorithm = "fp256bn"
					Case "Fp512BN"
						$idCurve = "FP512BN"
						$iAlgorithm = "fp512bn"
					Case "ANSSI FRP256v1"
						$idCurve = "FRP256V1"
						$iAlgorithm = "frp256v1"
					Case "Koblitz (Secp160k1)"
						$idCurve = "SECP160K1"
						$iAlgorithm = "secp160k1"
					Case "Koblitz (Secp192k1)"
						$idCurve = "SECP192K1"
						$iAlgorithm = "secp192k1"
					Case "Koblitz (Secp256k1)"
						$idCurve = "SECP256K1"
						$iAlgorithm = "secp256k1"
					Case "NUMSP256d1"
						$idCurve = "NUMSP256D1"
						$iAlgorithm = "numsp256d1"
					Case "NUMSP512d1"
						$idCurve = "NUMSP512D1"
						$iAlgorithm = "numsp512d1"
					Case "Oakley 192-bit"
						$idCurve = "OAKLEY192"
						$iAlgorithm = "oakley192"
					Case "Oakley 256-bit"
						$idCurve = "OAKLEY256"
						$iAlgorithm = "oakley256"
					Case "ANSI x9.62 Prime192v1"
						$idCurve = "PRIME192V1"
						$iAlgorithm = "prime192v1"
					Case "ANSI x9.62 Prime192v2"
						$idCurve = "PRIME192V2"
						$iAlgorithm = "prime192v2"
					Case "ANSI x9.62 Prime192v3"
						$idCurve = "PRIME192V3"
						$iAlgorithm = "prime192v3"
					Case "SEC2v1 Secp160r1"
						$idCurve = "SECP160R1"
						$iAlgorithm = "secp160r1"
					Case "SEC2v1 Secp160r2"
						$idCurve = "SECP160R2"
						$iAlgorithm = "secp160r2"
				EndSwitch
				If $sRead = "" and $rRead = "" Then
					$CMD = "roottk -keygen -info Keypair -algorithm " & $iAlgorithm & " | roottk -util unix2dos > " & @TempDir & "keypair.txt"
				ElseIf $sRead not = "" and $rRead = "" Then
					$CMD = "roottk -keygen -info Keypair -algorithm " & $iAlgorithm & " -key """ & $sRead  & """ | roottk -util unix2dos > " & @TempDir & "keypair.txt"
				Else
					$CMD = "roottk -keygen -info Keypair -algorithm " & $iAlgorithm & " | roottk -util unix2dos > " & @TempDir & "keypair.txt"
				EndIf
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$PrivateKey = IniRead(@TempDir & "keypair.txt", "Keypair", "Private", "Not found.")
				$PublicKey = IniRead(@TempDir & "keypair.txt", "Keypair", "Public", "Not found.")
				GUICtrlSetData($Edit5, $PrivateKey)
				GUICtrlSetData($Edit6, $PublicKey)
;				FileDelete(@TempDir & "keypair.txt")
				$CMD = "roottk -shred " & @TempDir & "keypair.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button8 ; Sign
				Switch GUICtrlRead($Combo2)
					Case "ECDSA (Secp256r1)"
						$idCurve = "ECDSA"
						$iAlgorithm = "ecdsa"
					Case "Brainpool256r1"
						$idCurve = "BRAINPOOL256R1"
						$iAlgorithm = "brainpool256r1"
					Case "Brainpool256t1"
						$idCurve = "BRAINPOOL256T1"
						$iAlgorithm = "brainpool256t1"
					Case "Brainpool512r1"
						$idCurve = "BRAINPOOL512R1"
						$iAlgorithm = "brainpool512r1"
					Case "Brainpool512t1"
						$idCurve = "BRAINPOOL512T1"
						$iAlgorithm = "brainpool512t1"
					Case "Brainpool160t1"
						$idCurve = "BRAINPOOL160T1"
						$iAlgorithm = "brainpool160t1"
					Case "Brainpool192t1"
						$idCurve = "BRAINPOOL192T1"
						$iAlgorithm = "brainpool192t1"
					Case "ED25519"
						$idCurve = "ED25519"
						$iAlgorithm = "ed25519"
					Case "SM2"
						$idCurve = "SM2P256V1"
						$iAlgorithm = "sm2p256v1"
					Case "SM9"
						$idCurve = "SM9P256V1"
						$iAlgorithm = "sm9p256v1"
					Case "GOST R 34.10-2012_A"
						$idCurve = "ECGOST2012A"
						$iAlgorithm = "ecgost2012A"
					Case "GOST R 34.10-2012_B"
						$idCurve = "ECGOST2012B"
						$iAlgorithm = "ecgost2012B"
					Case "GOST R 34.10-2001_A"
						$idCurve = "ECGOST2001A"
						$iAlgorithm = "ecgost2001A"
					Case "GOST R 34.10-2001_B"
						$idCurve = "ECGOST2001B"
						$iAlgorithm = "ecgost2001B"
					Case "GOST R 34.10-2001_C"
						$idCurve = "ECGOST2001C"
						$iAlgorithm = "ecgost2001C"
					Case "Fp256BN"
						$idCurve = "FP256BN"
						$iAlgorithm = "fp256bn"
					Case "Fp512BN"
						$idCurve = "FP512BN"
						$iAlgorithm = "fp512bn"
					Case "ANSSI FRP256v1"
						$idCurve = "FRP256V1"
						$iAlgorithm = "frp256v1"
					Case "Koblitz (Secp160k1)"
						$idCurve = "SECP160K1"
						$iAlgorithm = "secp160k1"
					Case "Koblitz (Secp192k1)"
						$idCurve = "SECP192K1"
						$iAlgorithm = "secp192k1"
					Case "Koblitz (Secp256k1)"
						$idCurve = "SECP256K1"
						$iAlgorithm = "secp256k1"
					Case "NUMSP256d1"
						$idCurve = "NUMSP256D1"
						$iAlgorithm = "numsp256d1"
					Case "NUMSP512d1"
						$idCurve = "NUMSP512D1"
						$iAlgorithm = "numsp512d1"
					Case "Oakley 192-bit"
						$idCurve = "OAKLEY192"
						$iAlgorithm = "oakley192"
					Case "Oakley 256-bit"
						$idCurve = "OAKLEY256"
						$iAlgorithm = "oakley256"
					Case "ANSI x9.62 Prime192v1"
						$idCurve = "PRIME192V1"
						$iAlgorithm = "prime192v1"
					Case "ANSI x9.62 Prime192v2"
						$idCurve = "PRIME192V2"
						$iAlgorithm = "prime192v2"
					Case "ANSI x9.62 Prime192v3"
						$idCurve = "PRIME192V3"
						$iAlgorithm = "prime192v3"
					Case "SEC2v1 Secp160r1"
						$idCurve = "SECP160R1"
						$iAlgorithm = "secp160r1"
					Case "SEC2v1 Secp160r2"
						$idCurve = "SECP160R2"
						$iAlgorithm = "secp160r2"
				EndSwitch
				Switch GUICtrlRead($Combo3)
					Case "BLAKE2b256"
						$idHash = "BLAKE2B256"
						$iHash = "blake2b256"
					Case "BLAKE2b512"
						$idHash = "BLAKE2B512"
						$iHash = "blake2b512"
					Case "BLAKE2s256"
						$idHash = "BLAKE2S256"
						$iHash = "blake2s256"
					Case "SHA256"
						$idHash = "SHA256"
						$iHash = "sha256"
					Case "SHA512"
						$idHash = "SHA512"
						$iHash = "sha512"
					Case "SM3"
						$idHash = "SM3"
						$iHash = "sm3"
					Case "Streebog256"
						$idHash = "STREEBOG256"
						$iHash = "streebog256"
					Case "Streebog512"
						$idHash = "STREEBOG512"
						$iHash = "streebog512"
					Case "Whirlpool"
						$idHash = "WHIRLPOOL"
						$iHash = "whirlpool"
					Case "CubeHash"
						$idHash = "CUBEHASH"
						$iHash = "cubehash"
					Case "SHA3_256"
						$idHash = "SHA3_256"
						$iHash = "sha3_256"
					Case "SHA512_256"
						$idHash = "SHA512_256"
						$iHash = "sha512_256"
					Case "SHA3_512"
						$idHash = "SHA3_512"
						$iHash = "sha3_512"
					Case "RIPEMD128"
						$idHash = "RMD128"
						$iHash = "rmd128"
					Case "RIPEMD160"
						$idHash = "RMD160"
						$iHash = "rmd160"
					Case "RIPEMD256"
						$idHash = "RMD256"
						$iHash = "rmd256"
					Case "GOST94-CryptoPro"
						$idHash = "GOST94"
						$iHash = "gost94"
					Case "LSH256"
						$idHash = "LSH256"
						$iHash = "lsh256"
					Case "LSH512_256"
						$idHash = "LSH512_256"
						$iHash = "lsh512_256"
					Case "LSH512"
						$idHash = "LSH512"
						$iHash = "lsh512"
					Case "Keccak256"
						$idHash = "KECCAK256"
						$iHash = "keccak256"
					Case "Keccak512"
						$idHash = "KECCAK512"
						$iHash = "keccak512"
					Case "Skein256"
						$idHash = "SKEIN256"
						$iHash = "skein256"
					Case "Skein512_256"
						$idHash = "SKEIN512_256"
						$iHash = "skein512_256"
					Case "Skein512"
						$idHash = "SKEIN512"
						$iHash = "skein512"
					Case "Tiger"
						$idHash = "TIGER"
						$iHash = "tiger"
					Case "Groestl"
						$idHash = "GROESTL"
						$iHash = "groestl"
					Case "JH"
						$idHash = "JH"
						$iHash = "jh"
				EndSwitch
				Global $sRead = GUICtrlRead($Edit5)
				Global $rRead = GUICtrlRead($Edit6)
				Global $xRead = GUICtrlRead($Edit7)
				Global $sFile = GUICtrlRead($Input1)
				Select
					Case GUICtrlRead($Radio1) = $GUI_CHECKED
						$radioval = "File"
					Case GUICtrlRead($Radio2) = $GUI_CHECKED
						$radioval = "String"
				EndSelect
				If $radioval = "File" Then
					$CMD = "echo [Signature] > " & @TempDir & "Sign.txt & roottk -sign -algorithm " & $iAlgorithm  & " -md " & $iHash  & " -key " & $sRead & " < " & $sFile & " | roottk -util unix2dos >> " & @TempDir & "Sign.txt"
					RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				ElseIf $radioval = "String" Then
					$CMD = "echo [Signature] > " & @TempDir & "Sign.txt & busybox echo -n " & $xRead & " | roottk -sign -algorithm " & $iAlgorithm  & " -md " & $iHash  & " -key " & $sRead & " | roottk -util unix2dos >> " & @TempDir & "Sign.txt"
					RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				EndIf
				If $idCurve = "ED25519" Then
					$id = $idCurve
				Else
					$id = $idCurve & "-" & $idHash
				EndIf
				$Signature = IniRead(@TempDir & "Sign.txt", "Signature", $id, "Error.")
				GUICtrlSetData($Edit8, $Signature)
				FileDelete(@TempDir & "Sign.txt")

			Case $Button9
				ClipPut(GUICtrlRead($Edit5))

			Case $Button10
				Local $sData = ClipGet()
				GUICtrlSetData($Edit6, $sData)

			Case $Button38
				ClipPut(GUICtrlRead($Edit6))

			Case $Button14
				ClipPut(GUICtrlRead($Edit8))

			Case $Button13
				Local $sData = ClipGet()
				GUICtrlSetData($Edit8, $sData)

			Case $Button12 ; Verify
				Switch GUICtrlRead($Combo2)
					Case "ECDSA (Secp256r1)"
						$idCurve = "ECDSA"
						$iAlgorithm = "ecdsa"
					Case "Brainpool256r1"
						$idCurve = "BRAINPOOL256R1"
						$iAlgorithm = "brainpool256r1"
					Case "Brainpool256t1"
						$idCurve = "BRAINPOOL256T1"
						$iAlgorithm = "brainpool256t1"
					Case "Brainpool512r1"
						$idCurve = "BRAINPOOL512R1"
						$iAlgorithm = "brainpool512r1"
					Case "Brainpool512t1"
						$idCurve = "BRAINPOOL512T1"
						$iAlgorithm = "brainpool512t1"
					Case "Brainpool160t1"
						$idCurve = "BRAINPOOL160T1"
						$iAlgorithm = "brainpool160t1"
					Case "Brainpool192t1"
						$idCurve = "BRAINPOOL192T1"
						$iAlgorithm = "brainpool192t1"
					Case "ED25519"
						$idCurve = "ED25519"
						$iAlgorithm = "ed25519"
					Case "SM2"
						$idCurve = "SM2P256V1"
						$iAlgorithm = "sm2p256v1"
					Case "SM9"
						$idCurve = "SM9P256V1"
						$iAlgorithm = "sm9p256v1"
					Case "GOST R 34.10-2012_A"
						$idCurve = "ECGOST2012A"
						$iAlgorithm = "ecgost2012A"
					Case "GOST R 34.10-2012_B"
						$idCurve = "ECGOST2012B"
						$iAlgorithm = "ecgost2012B"
					Case "GOST R 34.10-2001_A"
						$idCurve = "ECGOST2001A"
						$iAlgorithm = "ecgost2001A"
					Case "GOST R 34.10-2001_B"
						$idCurve = "ECGOST2001B"
						$iAlgorithm = "ecgost2001B"
					Case "GOST R 34.10-2001_C"
						$idCurve = "ECGOST2001C"
						$iAlgorithm = "ecgost2001C"
					Case "Fp256BN"
						$idCurve = "FP256BN"
						$iAlgorithm = "fp256bn"
					Case "Fp512BN"
						$idCurve = "FP512BN"
						$iAlgorithm = "fp512bn"
					Case "ANSSI FRP256v1"
						$idCurve = "FRP256V1"
						$iAlgorithm = "frp256v1"
					Case "Koblitz (Secp160k1)"
						$idCurve = "SECP160K1"
						$iAlgorithm = "secp160k1"
					Case "Koblitz (Secp192k1)"
						$idCurve = "SECP192K1"
						$iAlgorithm = "secp192k1"
					Case "Koblitz (Secp256k1)"
						$idCurve = "SECP256K1"
						$iAlgorithm = "secp256k1"
					Case "NUMSP256d1"
						$idCurve = "NUMSP256D1"
						$iAlgorithm = "numsp256d1"
					Case "NUMSP512d1"
						$idCurve = "NUMSP512D1"
						$iAlgorithm = "numsp512d1"
					Case "Oakley 192-bit"
						$idCurve = "OAKLEY192"
						$iAlgorithm = "oakley192"
					Case "Oakley 256-bit"
						$idCurve = "OAKLEY256"
						$iAlgorithm = "oakley256"
					Case "ANSI x9.62 Prime192v1"
						$idCurve = "PRIME192V1"
						$iAlgorithm = "prime192v1"
					Case "ANSI x9.62 Prime192v2"
						$idCurve = "PRIME192V2"
						$iAlgorithm = "prime192v2"
					Case "ANSI x9.62 Prime192v3"
						$idCurve = "PRIME192V3"
						$iAlgorithm = "prime192v3"
					Case "SEC2v1 Secp160r1"
						$idCurve = "SECP160R1"
						$iAlgorithm = "secp160r1"
					Case "SEC2v1 Secp160r2"
						$idCurve = "SECP160R2"
						$iAlgorithm = "secp160r2"
				EndSwitch
				Switch GUICtrlRead($Combo3)
					Case "BLAKE2b256"
						$idHash = "BLAKE2B256"
						$iHash = "blake2b256"
					Case "BLAKE2b512"
						$idHash = "BLAKE2B512"
						$iHash = "blake2b512"
					Case "BLAKE2s256"
						$idHash = "BLAKE2S256"
						$iHash = "blake2s256"
					Case "SHA256"
						$idHash = "SHA256"
						$iHash = "sha256"
					Case "SHA512"
						$idHash = "SHA512"
						$iHash = "sha512"
					Case "SM3"
						$idHash = "SM3"
						$iHash = "sm3"
					Case "Streebog256"
						$idHash = "STREEBOG256"
						$iHash = "streebog256"
					Case "Streebog512"
						$idHash = "STREEBOG512"
						$iHash = "streebog512"
					Case "Whirlpool"
						$idHash = "WHIRLPOOL"
						$iHash = "whirlpool"
					Case "SHA3_256"
						$idHash = "SHA3_256"
						$iHash = "sha3_256"
					Case "SHA512_256"
						$idHash = "SHA512_256"
						$iHash = "sha512_256"
					Case "SHA3_512"
						$idHash = "SHA3_512"
						$iHash = "sha3_512"
					Case "RIPEMD128"
						$idHash = "RMD128"
						$iHash = "rmd128"
					Case "RIPEMD160"
						$idHash = "RMD160"
						$iHash = "rmd160"
					Case "RIPEMD256"
						$idHash = "RMD256"
						$iHash = "rmd256"
					Case "GOST94-CryptoPro"
						$idHash = "GOST94"
						$iHash = "gost94"
					Case "LSH256"
						$idHash = "LSH256"
						$iHash = "lsh256"
					Case "LSH512_256"
						$idHash = "LSH512_256"
						$iHash = "lsh512_256"
					Case "LSH512"
						$idHash = "LSH512"
						$iHash = "lsh512"
					Case "Keccak256"
						$idHash = "KECCAK256"
						$iHash = "keccak256"
					Case "Keccak512"
						$idHash = "KECCAK512"
						$iHash = "keccak512"
					Case "Skein256"
						$idHash = "SKEIN256"
						$iHash = "skein256"
					Case "Skein512_256"
						$idHash = "SKEIN512_256"
						$iHash = "skein512_256"
					Case "Skein512"
						$idHash = "SKEIN512"
						$iHash = "skein512"
					Case "Tiger"
						$idHash = "TIGER"
						$iHash = "tiger"
					Case "Groestl"
						$idHash = "GROESTL"
						$iHash = "groestl"
					Case "JH"
						$idHash = "JH"
						$iHash = "jh"
				EndSwitch
				Global $sRead = GUICtrlRead($Edit5)
				Global $rRead = GUICtrlRead($Edit6)
				Global $xRead = GUICtrlRead($Edit7)
				Global $yRead = GUICtrlRead($Edit8)
				Global $sFile = GUICtrlRead($Input1)
				Select
					Case GUICtrlRead($Radio1) = $GUI_CHECKED
						$radioval = "File"
					Case GUICtrlRead($Radio2) = $GUI_CHECKED
						$radioval = "String"
				EndSelect
				If $radioval = "File" Then
					$CMD = "roottk -verify -key " & $rRead & " -signature " & $yRead & " -algorithm " & $iAlgorithm  & " -md " & $iHash  & " < " & $sFile & " > " & @TempDir & "Signature.txt"
					RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				ElseIf $radioval = "String" Then
					$CMD = "busybox echo -n " & $xRead & " | roottk -verify -key " & $rRead & " -signature " & $yRead & " -algorithm " & $iAlgorithm  & " -md " & $iHash  & " > " & @TempDir & "Signature.txt"
					RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				EndIf
				Local $sFileRead = FileRead(@TempDir & "Signature.txt")
				MsgBox($MB_SYSTEMMODAL, "", "Signature Verification:" & @CRLF & $sFileRead)
				FileDelete(@TempDir & "Signature.txt")

			Case $Button11
				Local $sFilePath = FileOpenDialog("Open a file", "", "All files (*.*)")
				If @error Then
					ContinueLoop
				EndIf
				GUICtrlSetData($Input1, $sFilePath)

			Case $Button15 ; Generate Keypair for Asymmetric Encryption
				Global $sRead = GUICtrlRead($Edit9)
				Global $rRead = GUICtrlRead($Edit10)
				Switch GUICtrlRead($Combo4)
					Case "ECDSA (Secp256r1)"
						$iAlgorithm = "ecdsa"
					Case "Brainpool256r1"
						$iAlgorithm = "brainpool256r1"
					Case "Brainpool256t1"
						$iAlgorithm = "brainpool256t1"
;					Case "Brainpool512r1"
;						$iAlgorithm = "brainpool512r1"
					Case "Brainpool512t1"
						$iAlgorithm = "brainpool512t1"
					Case "Brainpool160t1"
						$iAlgorithm = "brainpool160t1"
					Case "Brainpool192t1"
						$iAlgorithm = "brainpool192t1"
					Case "SM2"
						$iAlgorithm = "sm2p256v1"
					Case "SM9"
						$iAlgorithm = "sm9p256v1"
					Case "GOST R 34.10-2012_A"
						$iAlgorithm = "ecgost2012A"
					Case "GOST R 34.10-2012_B"
						$iAlgorithm = "ecgost2012B"
					Case "GOST R 34.10-2001_A"
						$iAlgorithm = "ecgost2001A"
					Case "GOST R 34.10-2001_B"
						$iAlgorithm = "ecgost2001B"
					Case "GOST R 34.10-2001_C"
						$iAlgorithm = "ecgost2001C"
					Case "Fp256BN"
						$iAlgorithm = "fp256bn"
					Case "Fp512BN"
						$iAlgorithm = "fp512bn"
					Case "ANSSI FRP256v1"
						$iAlgorithm = "frp256v1"
					Case "Koblitz (Secp160k1)"
						$iAlgorithm = "secp160k1"
					Case "Koblitz (Secp192k1)"
						$iAlgorithm = "secp192k1"
					Case "Koblitz (Secp256k1)"
						$iAlgorithm = "secp256k1"
;					Case "NUMSP256d1"
;						$iAlgorithm = "numsp256d1"
					Case "NUMSP512d1"
						$iAlgorithm = "numsp512d1"
					Case "Oakley 192-bit"
						$iAlgorithm = "oakley192"
					Case "Oakley 256-bit"
						$iAlgorithm = "oakley256"
					Case "ANSI x9.62 Prime192v1"
						$iAlgorithm = "prime192v1"
					Case "ANSI x9.62 Prime192v2"
						$iAlgorithm = "prime192v2"
					Case "ANSI x9.62 Prime192v3"
						$iAlgorithm = "prime192v3"
					Case "SEC2v1 Secp160r1"
						$iAlgorithm = "secp160r1"
					Case "SEC2v1 Secp160r2"
						$iAlgorithm = "secp160r2"
				EndSwitch
				If $sRead = "" and $rRead = "" Then
					$CMD = "roottk -keygen -info Keypair -algorithm " & $iAlgorithm & " | roottk -util unix2dos > " & @TempDir & "keypair.txt"
				ElseIf $sRead not = "" and $rRead = "" Then
					$CMD = "roottk -keygen -info Keypair -algorithm " & $iAlgorithm & " -key """ & $sRead  & """ | roottk -util unix2dos > " & @TempDir & "keypair.txt"
				Else
					$CMD = "roottk -keygen -info Keypair -algorithm " & $iAlgorithm & " | roottk -util unix2dos > " & @TempDir & "keypair.txt"
				EndIf
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$PrivateKey = IniRead(@TempDir & "keypair.txt", "Keypair", "Private", "Not found.")
				$PublicKey = IniRead(@TempDir & "keypair.txt", "Keypair", "Public", "Not found.")
				GUICtrlSetData($Edit9, $PrivateKey)
				GUICtrlSetData($Edit10, $PublicKey)
;				FileDelete(@TempDir & "keypair.txt")
				$CMD = "roottk -shred " & @TempDir & "keypair.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button16
				ClipPut(GUICtrlRead($Edit9))

			Case $Button17
				ClipPut(GUICtrlRead($Edit10))

			Case $Button21
				Local $sData = ClipGet()
				GUICtrlSetData($Edit10, $sData)

			Case $Button20
				ClipPut(GUICtrlRead($Edit11))

			Case $Button22
				Local $sData = ClipGet()
				GUICtrlSetData($Edit11, $sData)

			Case $Button56
				ClipPut(GUICtrlRead($Edit26))

			Case $Button55
				Local $sData = ClipGet()
				GUICtrlSetData($Edit26, $sData)

			Case $Button18 ; Encrypt
				Switch GUICtrlRead($Combo4)
					Case "ECDSA (Secp256r1)"
						$iAlgorithm = "ecdsa"
					Case "Brainpool256r1"
						$iAlgorithm = "brainpool256r1"
					Case "Brainpool256t1"
						$iAlgorithm = "brainpool256t1"
;					Case "Brainpool512r1"
;						$iAlgorithm = "brainpool512r1"
					Case "Brainpool512t1"
						$iAlgorithm = "brainpool512t1"
					Case "Brainpool160t1"
						$iAlgorithm = "brainpool160t1"
					Case "Brainpool192t1"
						$iAlgorithm = "brainpool192t1"
					Case "SM2"
						$iAlgorithm = "sm2p256v1"
					Case "SM9"
						$iAlgorithm = "sm9p256v1"
					Case "GOST R 34.10-2012_A"
						$iAlgorithm = "ecgost2012A"
					Case "GOST R 34.10-2012_B"
						$iAlgorithm = "ecgost2012B"
					Case "GOST R 34.10-2001_A"
						$iAlgorithm = "ecgost2001A"
					Case "GOST R 34.10-2001_B"
						$iAlgorithm = "ecgost2001B"
					Case "GOST R 34.10-2001_C"
						$iAlgorithm = "ecgost2001C"
					Case "Fp256BN"
						$iAlgorithm = "fp256bn"
					Case "Fp512BN"
						$iAlgorithm = "fp512bn"
					Case "ANSSI FRP256v1"
						$iAlgorithm = "frp256v1"
					Case "Koblitz (Secp160k1)"
						$iAlgorithm = "secp160k1"
					Case "Koblitz (Secp192k1)"
						$iAlgorithm = "secp192k1"
					Case "Koblitz (Secp256k1)"
						$iAlgorithm = "secp256k1"
;					Case "NUMSP256d1"
;						$iAlgorithm = "numsp256d1"
					Case "NUMSP512d1"
						$iAlgorithm = "numsp512d1"
					Case "Oakley 192-bit"
						$iAlgorithm = "oakley192"
					Case "Oakley 256-bit"
						$iAlgorithm = "oakley256"
					Case "ANSI x9.62 Prime192v1"
						$iAlgorithm = "prime192v1"
					Case "ANSI x9.62 Prime192v2"
						$iAlgorithm = "prime192v2"
					Case "ANSI x9.62 Prime192v3"
						$iAlgorithm = "prime192v3"
					Case "SEC2v1 Secp160r1"
						$iAlgorithm = "secp160r1"
					Case "SEC2v1 Secp160r2"
						$iAlgorithm = "secp160r2"
				EndSwitch
				Local $PublicKey = GUICtrlRead($Edit10)
				If GUICtrlRead($Edit11) = "" Then
					GUICtrlSetData($Edit11, "null")
				EndIf
				Local $PlainText = GUICtrlRead($Edit11)
				$CMD = "busybox echo -n """ & $PlainText & """ > " & @TempDir & "Plaintext.txt & roottk -pkeyutl enc -algorithm " & $iAlgorithm & " -key " & $PublicKey & " < " & @TempDir & "Plaintext.txt | roottk -util hexdec | roottk -util b32enc+ > " & @TempDir & "Ciphertext.txt"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$Result = FileRead(@TempDir & "Ciphertext.txt")
;				$string = StringSplit($Result, @CRLF)
;				GUICtrlSetData($Edit26, $string[1])
;				GUICtrlSetData($Edit11, $string[1])
				$LineFeedStrip = StringReplace($Result, @LF, "")
				GUICtrlSetData($Edit26, $LineFeedStrip)
;				FileDelete(@TempDir & "Plaintext.txt")
;				FileDelete(@TempDir & "Ciphertext.txt")
				$CMD = "roottk -shred " & @TempDir & "Plaintext..txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$CMD = "roottk -shred " & @TempDir & "Ciphertext.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button19 ; Decrypt
				Switch GUICtrlRead($Combo4)
					Case "ECDSA (Secp256r1)"
						$iAlgorithm = "ecdsa"
					Case "Brainpool256r1"
						$iAlgorithm = "brainpool256r1"
					Case "Brainpool256t1"
						$iAlgorithm = "brainpool256t1"
;					Case "Brainpool512r1"
;						$iAlgorithm = "brainpool512r1"
					Case "Brainpool512t1"
						$iAlgorithm = "brainpool512t1"
					Case "Brainpool160t1"
						$iAlgorithm = "brainpool160t1"
					Case "Brainpool192t1"
						$iAlgorithm = "brainpool192t1"
					Case "SM2"
						$iAlgorithm = "sm2p256v1"
					Case "SM9"
						$iAlgorithm = "sm9p256v1"
					Case "GOST R 34.10-2012_A"
						$iAlgorithm = "ecgost2012A"
					Case "GOST R 34.10-2012_B"
						$iAlgorithm = "ecgost2012B"
					Case "GOST R 34.10-2001_A"
						$iAlgorithm = "ecgost2001A"
					Case "GOST R 34.10-2001_B"
						$iAlgorithm = "ecgost2001B"
					Case "GOST R 34.10-2001_C"
						$iAlgorithm = "ecgost2001C"
					Case "Fp256BN"
						$iAlgorithm = "fp256bn"
					Case "Fp512BN"
						$iAlgorithm = "fp512bn"
					Case "ANSSI FRP256v1"
						$iAlgorithm = "frp256v1"
					Case "Koblitz (Secp160k1)"
						$iAlgorithm = "secp160k1"
					Case "Koblitz (Secp192k1)"
						$iAlgorithm = "secp192k1"
					Case "Koblitz (Secp256k1)"
						$iAlgorithm = "secp256k1"
;					Case "NUMSP256d1"
;						$iAlgorithm = "numsp256d1"
					Case "NUMSP512d1"
						$iAlgorithm = "numsp512d1"
					Case "Oakley 192-bit"
						$iAlgorithm = "oakley192"
					Case "Oakley 256-bit"
						$iAlgorithm = "oakley256"
					Case "ANSI x9.62 Prime192v1"
						$iAlgorithm = "prime192v1"
					Case "ANSI x9.62 Prime192v2"
						$iAlgorithm = "prime192v2"
					Case "ANSI x9.62 Prime192v3"
						$iAlgorithm = "prime192v3"
					Case "SEC2v1 Secp160r1"
						$iAlgorithm = "secp160r1"
					Case "SEC2v1 Secp160r2"
						$iAlgorithm = "secp160r2"
				EndSwitch
				Local $PrivateKey = GUICtrlRead($Edit9)
				Local $CipherText = GUICtrlRead($Edit26)
				$CMD = "busybox echo -n """ & $CipherText & """ | roottk -util b32dec+ | roottk -util hexenc > " & @TempDir & "Ciphertext.txt & roottk -pkeyutl dec -algorithm " & $iAlgorithm & " -key " & $PrivateKey & " < " & @TempDir & "Ciphertext.txt > " & @TempDir & "Plaintext.txt"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$Result = FileRead(@TempDir & "Plaintext.txt")
;				$string = StringSplit($Result, @CRLF)
;				GUICtrlSetData($Edit11, $string[1])
				$LineFeedStrip = StringReplace($Result, @LF, "")
				GUICtrlSetData($Edit11, $LineFeedStrip)
;				FileDelete("Plaintext.txt")
;				FileDelete("Ciphertext.txt")
				$CMD = "roottk -shred " & @TempDir & "Plaintext.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$CMD = "roottk -shred " & @TempDir & "Ciphertext.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button25
				Local $sFilePath = FileOpenDialog("Open a file", "", "All files (*.*)")
				If @error Then
					ContinueLoop
				EndIf
				GUICtrlSetData($Input2, $sFilePath)

			Case $Button30
				Local $sFilePath = FileSaveDialog("Save as", "", "All files (*.*)")
				If @error Then
					ContinueLoop
				EndIf
				GUICtrlSetData($Input3, $sFilePath)

			Case $Button24
				ClipPut(GUICtrlRead($Edit15))

			Case $Button23
				Local $sData = ClipGet()
				GUICtrlSetData($Edit15, $sData)

			Case $Button26
				ClipPut(GUICtrlRead($Edit14))

			Case $Button27 ; Generate Symmetric Key for Encryption
				Switch GUICtrlRead($iBulk)
					Case "AES (Rijndael)"
						$iAlgorithm = "aes"
						$Bits = 256
					Case "Anubis"
						$iAlgorithm = "anubis"
						$Bits = 128
					Case "ARIA"
						$iAlgorithm = "aria"
						$Bits = 256
					Case "Chacha20Poly1305"
						If GUICtrlRead($Checkbox1) = $GUI_CHECKED Then
							$iAlgorithm = "chacha20poly1305"
						Else
							$iAlgorithm = "chacha20"
						EndIf
						$Bits = 256
					Case "Serpent"
						$iAlgorithm = "serpent"
						$Bits = 256
					Case "Kuznechik"
						$iAlgorithm = "grasshopper"
						$Bits = 256
					Case "SEED"
						$iAlgorithm = "seed"
						$Bits = 256
					Case "Simon128"
						$iAlgorithm = "simon128"
						$Bits = 256
					Case "Speck128"
						$iAlgorithm = "speck128"
						$Bits = 256
					Case "Simon64"
						$iAlgorithm = "simon64"
						$Bits = 128
					Case "Speck64"
						$iAlgorithm = "speck64"
						$Bits = 128
					Case "SM4"
						$iAlgorithm = "sm4"
						$Bits = 128
					Case "Twofish"
						$iAlgorithm = "twofish"
						$Bits = 256
					Case "HC128 (no AEAD)"
						$iAlgorithm = "hc128"
						$Bits = 128
					Case "HC256 (no AEAD)"
						$iAlgorithm = "hc256"
						$Bits = 256
					Case "MISTY1"
						$iAlgorithm = "misty1"
						$Bits = 128
					Case "GOST89-CryptoPro"
						$iAlgorithm = "gost89"
						$Bits = 256
					Case "Magma"
						$iAlgorithm = "magma"
						$Bits = 256
					Case "Camellia"
						$iAlgorithm = "camellia"
						$Bits = 256
					Case "Ascon 1.2"
						$iAlgorithm = "ascon"
						$Bits = 128
					Case "Grain128a"
						$iAlgorithm = "grain"
						$Bits = 128
					Case "Rabbit (no AEAD)"
						$iAlgorithm = "rabbit"
						$Bits = 128
					Case "ZUC-128 (no AEAD)"
						$iAlgorithm = "zuc128"
						$Bits = 128
					Case "ZUC-256 (no AEAD)"
						$iAlgorithm = "zuc256"
						$Bits = 256
					Case "LEA"
						$iAlgorithm = "lea"
						$Bits = 256
					Case "Trivium (no AEAD)"
						$iAlgorithm = "trivium"
						$Bits = 80
					Case "HIGHT"
						$iAlgorithm = "hight"
						$Bits = 128
					Case "Threefish (no AEAD)"
						$iAlgorithm = "threefish"
						$Bits = 256
					Case "Snow3G (no AEAD)"
						$iAlgorithm = "snow3g"
						$Bits = 128
					Case "PRESENT"
						$iAlgorithm = "present"
						$Bits = 128
					Case "TWINE"
						$iAlgorithm = "twine"
						$Bits = 128
				EndSwitch
				$CMD = "roottk -rand -bits " &$Bits & " > " & @TempDir & "Key.txt"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$Key = FileRead(@TempDir & "Key.txt")
				$LineFeedStrip = StringReplace($Key, @LF, "")
				GUICtrlSetData($Edit12, $LineFeedStrip)
;				FileDelete("Key.txt")
				$CMD = "roottk -shred " & @TempDir & "Key.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button49 ; Generate IV for Encryption
				Switch GUICtrlRead($iBulk)
					Case "AES (Rijndael)"
						$iAlgorithm = "aes"
						$Bits = 128
					Case "Anubis"
						$iAlgorithm = "anubis"
						$Bits = 128
					Case "ARIA"
						$iAlgorithm = "aria"
						$Bits = 128
					Case "Chacha20Poly1305"
						If GUICtrlRead($Checkbox1) = $GUI_CHECKED Then
							$iAlgorithm = "chacha20poly1305"
							$Bits = 0
						Else
							$iAlgorithm = "chacha20"
							$Bits = 192
						EndIf
					Case "Serpent"
						$iAlgorithm = "serpent"
						$Bits = 128
					Case "Kuznechik"
						$iAlgorithm = "grasshopper"
						$Bits = 128
					Case "SEED"
						$iAlgorithm = "seed"
						$Bits = 128
					Case "Simon128"
						$iAlgorithm = "simon128"
						$Bits = 128
					Case "Speck128"
						$iAlgorithm = "speck128"
						$Bits = 128
					Case "Simon64"
						$iAlgorithm = "simon64"
						$Bits = 64
					Case "Speck64"
						$iAlgorithm = "speck64"
						$Bits = 64
					Case "SM4"
						$iAlgorithm = "sm4"
						$Bits = 128
					Case "Twofish"
						$iAlgorithm = "twofish"
						$Bits = 128
					Case "HC128 (no AEAD)"
						$iAlgorithm = "hc128"
						$Bits = 128
					Case "HC256 (no AEAD)"
						$iAlgorithm = "hc256"
						$Bits = 256
					Case "MISTY1"
						$iAlgorithm = "misty1"
						$Bits = 64
					Case "GOST89-CryptoPro"
						$iAlgorithm = "gost89"
						$Bits = 64
					Case "Magma"
						$iAlgorithm = "magma"
						$Bits = 64
					Case "Camellia"
						$iAlgorithm = "camellia"
						$Bits = 128
					Case "Ascon 1.2"
						$iAlgorithm = "ascon"
						$Bits = 0
					Case "Grain128a"
						$iAlgorithm = "grain"
						$Bits = 0
					Case "Rabbit (no AEAD)"
						$iAlgorithm = "rabbit"
						$Bits = 64
					Case "ZUC-128 (no AEAD)"
						$iAlgorithm = "zuc128"
						$Bits = 128
					Case "ZUC-256 (no AEAD)"
						$iAlgorithm = "zuc256"
						$Bits = 184
					Case "LEA"
						$iAlgorithm = "lea"
						$Bits = 128
					Case "Trivium (no AEAD)"
						$iAlgorithm = "trivium"
						$Bits = 80
					Case "HIGHT"
						$iAlgorithm = "hight"
						$Bits = 64
					Case "Threefish (no AEAD)"
						$iAlgorithm = "threefish"
						$Bits = 256
					Case "Snow3G (no AEAD)"
						$iAlgorithm = "snow3g"
						$Bits = 0
					Case "PRESENT"
						$iAlgorithm = "present"
						$Bits = 64
					Case "TWINE"
						$iAlgorithm = "twine"
						$Bits = 64
				EndSwitch
				$CMD = "roottk -rand -bits " &$Bits & " > " & @TempDir & "Key.txt"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$Key = FileRead(@TempDir & "Key.txt")
				$LineFeedStrip = StringReplace($Key, @LF, "")
				GUICtrlSetData($Edit25, $LineFeedStrip)
;				FileDelete("Key.txt")
				$CMD = "roottk -shred " & @TempDir & "Key.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button28 ; Encrypt with Symmetric Key
				Switch GUICtrlRead($iBulk)
					Case "AES (Rijndael)"
						$iAlgorithm = "aes"
					Case "Anubis"
						$iAlgorithm = "anubis"
					Case "ARIA"
						$iAlgorithm = "aria"
					Case "Chacha20Poly1305"
						If GUICtrlRead($Checkbox1) = $GUI_CHECKED Then
							$iAlgorithm = "chacha20poly1305"
						Else
							$iAlgorithm = "chacha20"
						EndIf
					Case "Serpent"
						$iAlgorithm = "serpent"
					Case "Kuznechik"
						$iAlgorithm = "grasshopper"
					Case "SEED"
						$iAlgorithm = "seed"
					Case "Simon128"
						$iAlgorithm = "simon128"
					Case "Speck128"
						$iAlgorithm = "speck128"
					Case "Simon64"
						$iAlgorithm = "simon64"
					Case "Speck64"
						$iAlgorithm = "speck64"
					Case "SM4"
						$iAlgorithm = "sm4"
					Case "Twofish"
						$iAlgorithm = "twofish"
					Case "HC128 (no AEAD)"
						$iAlgorithm = "hc128"
					Case "HC256 (no AEAD)"
						$iAlgorithm = "hc256"
					Case "MISTY1"
						$iAlgorithm = "misty1"
					Case "GOST89-CryptoPro"
						$iAlgorithm = "gost89"
					Case "Magma"
						$iAlgorithm = "magma"
					Case "Camellia"
						$iAlgorithm = "camellia"
					Case "Ascon 1.2"
						$iAlgorithm = "ascon"
					Case "Grain128a"
						$iAlgorithm = "grain"
					Case "Rabbit (no AEAD)"
						$iAlgorithm = "rabbit"
					Case "ZUC-128 (no AEAD)"
						$iAlgorithm = "zuc128"
					Case "ZUC-256 (no AEAD)"
						$iAlgorithm = "zuc256"
					Case "LEA"
						$iAlgorithm = "lea"
					Case "Trivium (no AEAD)"
						$iAlgorithm = "trivium"
					Case "HIGHT"
						$iAlgorithm = "hight"
					Case "Threefish (no AEAD)"
						$iAlgorithm = "threefish"
					Case "Snow3G (no AEAD)"
						$iAlgorithm = "snow3g"
					Case "PRESENT"
						$iAlgorithm = "present"
					Case "TWINE"
						$iAlgorithm = "twine"
				EndSwitch
				Global $sRead = GUICtrlRead($Edit14)
				Global $rRead = GUICtrlRead($Edit15)
				Global $xRead = GUICtrlRead($Edit12)
				Global $sFile = GUICtrlRead($Input2)
				Global $xFile = GUICtrlRead($Input3)
				Global $yRead = GUICtrlRead($Input4)
				Global $aRead = GUICtrlRead($Edit25)
				Global $Mode = GUICtrlRead($Combo8)
				Global $DMode = GUICtrlRead($Combo12)
				Select
					Case GUICtrlRead($Radio3) = $GUI_CHECKED
						$radioval = "File"
					Case GUICtrlRead($Radio4) = $GUI_CHECKED
						$radioval = "String"
				EndSelect
				If GUICtrlRead($Checkbox4) = $GUI_CHECKED Then
					Global $command = "b64enc+"
				Else
					Global $command = "b32enc+"
				EndIf
				If $radioval = "File" Then
					If GUICtrlRead($Checkbox1) = $GUI_CHECKED Then
						$CMD = "roottk -crypt enc -mode " & $Mode & " -info " & $yRead & " -cipher " & $iAlgorithm & " -key """ & $xRead & """ < " & $sFile & " > " & $xFile
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
					Else
						$CMD = "roottk -crypt enc -mode " & $DMode & " -cipher " & $iAlgorithm & " -key " & $xRead & " -iv """ & $aRead & """ < " & $sFile & " > " & $xFile
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
					EndIf
					MsgBox($MB_SYSTEMMODAL, "", "Encryption" & @CRLF & " Done")
				ElseIf $radioval = "String" Then
					If GUICtrlRead($Checkbox1) = $GUI_CHECKED Then
						$CMD = "busybox echo -n " & $sRead & " | roottk -crypt enc -mode " & $Mode & " -info " & $yRead & " -cipher " & $iAlgorithm & " -key """ & $xRead & """ | roottk -util " & $command & " > " & @TempDir & "Ciphertext.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
					Else
						$CMD = "busybox echo -n " & $sRead & " | roottk -crypt enc -mode " & $DMode & " -cipher " & $iAlgorithm & " -key """ & $xRead & """ -iv """ & $aRead & """ | roottk -util " & $command & " > " & @TempDir & "Ciphertext.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
					EndIf
					$Result = FileRead(@TempDir & "Ciphertext.txt")
					$LineFeedStrip = StringReplace($Result, @LF, "")
					GUICtrlSetData($Edit15, $LineFeedStrip)
;					FileDelete(@TempDir & "Ciphertext.txt")
					$CMD = "roottk -shred " & @TempDir & "Ciphertext.txt -iter 5"
					RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				EndIf

			Case $Button29 ; Decrypt with Symmetric Key
				Switch GUICtrlRead($iBulk)
					Case "AES (Rijndael)"
						$iAlgorithm = "aes"
					Case "Anubis"
						$iAlgorithm = "anubis"
					Case "ARIA"
						$iAlgorithm = "aria"
					Case "Chacha20Poly1305"
						If GUICtrlRead($Checkbox1) = $GUI_CHECKED Then
							$iAlgorithm = "chacha20poly1305"
						Else
							$iAlgorithm = "chacha20"
						EndIf
					Case "Serpent"
						$iAlgorithm = "serpent"
					Case "Kuznechik"
						$iAlgorithm = "grasshopper"
					Case "SEED"
						$iAlgorithm = "seed"
					Case "Simon128"
						$iAlgorithm = "simon128"
					Case "Speck128"
						$iAlgorithm = "speck128"
					Case "Simon64"
						$iAlgorithm = "simon64"
					Case "Speck64"
						$iAlgorithm = "speck64"
					Case "SM4"
						$iAlgorithm = "sm4"
					Case "Twofish"
						$iAlgorithm = "twofish"
					Case "HC128 (no AEAD)"
						$iAlgorithm = "hc128"
					Case "HC256 (no AEAD)"
						$iAlgorithm = "hc256"
					Case "MISTY1"
						$iAlgorithm = "misty1"
					Case "GOST89-CryptoPro"
						$iAlgorithm = "gost89"
					Case "Magma"
						$iAlgorithm = "magma"
					Case "Camellia"
						$iAlgorithm = "camellia"
					Case "Ascon 1.2"
						$iAlgorithm = "ascon"
					Case "Grain128a"
						$iAlgorithm = "grain"
					Case "Rabbit (no AEAD)"
						$iAlgorithm = "rabbit"
					Case "ZUC-128 (no AEAD)"
						$iAlgorithm = "zuc128"
					Case "ZUC-256 (no AEAD)"
						$iAlgorithm = "zuc256"
					Case "LEA"
						$iAlgorithm = "lea"
					Case "Trivium (no AEAD)"
						$iAlgorithm = "trivium"
					Case "HIGHT"
						$iAlgorithm = "hight"
					Case "Threefish (no AEAD)"
						$iAlgorithm = "threefish"
					Case "Snow3G (no AEAD)"
						$iAlgorithm = "snow3g"
					Case "PRESENT"
						$iAlgorithm = "present"
					Case "TWINE"
						$iAlgorithm = "twine"
				EndSwitch
				Global $sRead = GUICtrlRead($Edit14)
				Global $rRead = GUICtrlRead($Edit15)
				Global $xRead = GUICtrlRead($Edit12)
				Global $sFile = GUICtrlRead($Input2)
				Global $xFile = GUICtrlRead($Input3)
				Global $yRead = GUICtrlRead($Input4)
				Global $aRead = GUICtrlRead($Edit25)
				Global $Mode = GUICtrlRead($Combo8)
				Global $DMode = GUICtrlRead($Combo12)
				Select
					Case GUICtrlRead($Radio3) = $GUI_CHECKED
						$radioval = "File"
					Case GUICtrlRead($Radio4) = $GUI_CHECKED
						$radioval = "String"
				EndSelect
				If GUICtrlRead($Checkbox4) = $GUI_CHECKED Then
					Global $command = "b64dec+"
				Else
					Global $command = "b32dec+"
				EndIf
				If $radioval = "File" Then
					If GUICtrlRead($Checkbox1) = $GUI_CHECKED Then
						$CMD = "roottk -crypt dec -mode " & $Mode & " -info " & $yRead & " -cipher " & $iAlgorithm & " -key " & $xRead & " < " & $sFile & " > " & $xFile
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
					Else
						$CMD = "roottk -crypt dec -mode " & $DMode & " -key " & $xRead & " -cipher " & $iAlgorithm & " -iv """ & $aRead & """ < " & $sFile & " > " & $xFile
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
					EndIf
					MsgBox($MB_SYSTEMMODAL, "", "Decryption" & @CRLF & " Done")
				ElseIf $radioval = "String" Then
					If GUICtrlRead($Checkbox1) = $GUI_CHECKED Then
						$CMD = "busybox echo -n " & $rRead & " | roottk -util " & $command & " | roottk -crypt dec -mode " & $Mode & " -info " & $yRead & " -cipher " & $iAlgorithm & " -key " & $xRead & " > " & @TempDir & "Plaintext.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
					Else
						$CMD = "busybox echo -n " & $rRead & " | roottk -util " & $command & " | roottk -crypt dec -mode " & $DMode & " -key " & $xRead & " -cipher " & $iAlgorithm & " -iv """ & $aRead & """ > " & @TempDir & "Plaintext.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
					EndIf
					$Result = FileRead(@TempDir & "Plaintext.txt")
					GUICtrlSetData($Edit14, $Result)
;					FileDelete(@TempDir & "Plaintext.txt")
					$CMD = "roottk -shred " & @TempDir & "Plaintext.txt -iter 5"
					RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				EndIf

			Case $Button31
				Local $sFilePath = FileOpenDialog("Open a file", "", "All files (*.*)")
				If @error Then
					ContinueLoop
				EndIf
				GUICtrlSetData($Input5, $sFilePath)

			Case $Button34 ; Compute Digests
				Switch GUICtrlRead($Combo5)
					Case "BLAKE2b256"
						$idHash = "BLAKE2B256"
						$iHash = "blake2b256"
					Case "BLAKE2b512"
						$idHash = "BLAKE2B512"
						$iHash = "blake2b512"
					Case "BLAKE2s128"
						$idHash = "BLAKE2S128"
						$iHash = "blake2s128"
					Case "BLAKE2s256"
						$idHash = "BLAKE2S256"
						$iHash = "blake2s256"
					Case "SHA256"
						$idHash = "SHA256"
						$iHash = "sha256"
					Case "SHA512_256"
						$idHash = "SHA512_256"
						$iHash = "sha512_256"
					Case "SHA512"
						$idHash = "SHA512"
						$iHash = "sha512"
					Case "SM3"
						$idHash = "SM3"
						$iHash = "sm3"
					Case "Streebog256"
						$idHash = "STREEBOG256"
						$iHash = "streebog256"
					Case "Streebog512"
						$idHash = "STREEBOG512"
						$iHash = "streebog512"
					Case "CubeHash"
						$idHash = "CUBEHASH"
						$iHash = "cubehash"
					Case "Whirlpool"
						$idHash = "WHIRLPOOL"
						$iHash = "whirlpool"
					Case "SHA3_256"
						$idHash = "SHA3_256"
						$iHash = "sha3_256"
					Case "SHA3_512"
						$idHash = "SHA3_512"
						$iHash = "sha3_512"
					Case "RIPEMD128"
						$idHash = "RMD128"
						$iHash = "rmd128"
					Case "RIPEMD160"
						$idHash = "RMD160"
						$iHash = "rmd160"
					Case "RIPEMD256"
						$idHash = "RMD256"
						$iHash = "rmd256"
					Case "GOST94-CryptoPro"
						$idHash = "GOST94"
						$iHash = "gost94"
					Case "LSH256"
						$idHash = "LSH256"
						$iHash = "lsh256"
					Case "LSH512_256"
						$idHash = "LSH512_256"
						$iHash = "lsh512_256"
					Case "LSH512"
						$idHash = "LSH512"
						$iHash = "lsh512"
					Case "Keccak256"
						$idHash = "KECCAK256"
						$iHash = "keccak256"
					Case "Keccak512"
						$idHash = "KECCAK512"
						$iHash = "keccak512"
					Case "Skein256"
						$idHash = "SKEIN256"
						$iHash = "skein256"
					Case "Skein512_256"
						$idHash = "SKEIN512_256"
						$iHash = "skein512_256"
					Case "Skein512"
						$idHash = "SKEIN512"
						$iHash = "skein512"
					Case "SipHash"
						$idHash = "SIPHASH"
						$iHash = "siphash"
					Case "Poly1305"
						$idHash = "POLY1305"
						$iHash = "poly1305"
					Case "Tiger"
						$idHash = "TIGER"
						$iHash = "tiger"
					Case "Groestl"
						$idHash = "GROESTL"
						$iHash = "groestl"
					Case "JH"
						$idHash = "JH"
						$iHash = "jh"
				EndSwitch
				Select
					Case GUICtrlRead($Radio5) = $GUI_CHECKED
						$radioval = "File"
					Case GUICtrlRead($Radio6) = $GUI_CHECKED
						$radioval = "String"
				EndSelect
				Global $sRead = GUICtrlRead($Edit17)
				Global $rRead = GUICtrlRead($Edit18)
				Global $sFile = GUICtrlRead($Input5)
				If $radioval = "File" Then
					If GUICtrlRead($Checkbox2) = $GUI_CHECKED Then
						$CMD = "echo [Digest] > " & @TempDir & "Digest.txt & roottk -mac hmac -md " & $iHash & " -key """ & $rRead & """ < " & $sFile & " >> " & @TempDir & "Digest.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
						$id = "MAC-" & $idHash
						$Result = IniRead(@TempDir & "Digest.txt", "Digest", $id, "Error.")
						GUICtrlSetData($Edit16, $Result)
						FileDelete(@TempDir & "Digest.txt")
					Else
						$CMD = "roottk -digest - -md " & $iHash & " -key " & $rRead & " -key """ & $rRead & """ < " & $sFile & " > " & @TempDir & "Digest.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
						$Result = FileRead(@TempDir & "Digest.txt")
						GUICtrlSetData($Edit16, $Result)
						FileDelete(@TempDir & "Digest.txt")
					EndIf
				ElseIf $radioval = "String" Then
					If GUICtrlRead($Checkbox2) = $GUI_CHECKED Then
						$CMD = "echo [Digest] > " & @TempDir & "Digest.txt & busybox echo -n " & $sRead & " | roottk -mac hmac -md " & $iHash & " -key """ & $rRead & """ >> " & @TempDir & "Digest.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
						$id = "MAC-" & $idHash
						$Result = IniRead(@TempDir & "Digest.txt", "Digest", $id, "Error.")
						GUICtrlSetData($Edit16, $Result)
						FileDelete(@TempDir & "Digest.txt")
					Else
						$CMD = "busybox echo -n " & $sRead & " | roottk -digest - -md " & $iHash & " -key """ & $rRead & """ > " & @TempDir & "Digest.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
						$Result = FileRead(@TempDir & "Digest.txt")
						GUICtrlSetData($Edit16, $Result)
						FileDelete(@TempDir & "Digest.txt")
					EndIf
				EndIf

			Case $Button35 ; Check Digests
				Switch GUICtrlRead($Combo5)
					Case "BLAKE2b256"
						$idHash = "BLAKE2B256"
						$iHash = "blake2b256"
					Case "BLAKE2b512"
						$idHash = "BLAKE2B512"
						$iHash = "blake2b512"
					Case "BLAKE2s128"
						$idHash = "BLAKE2S128"
						$iHash = "blake2s128"
					Case "BLAKE2s256"
						$idHash = "BLAKE2S256"
						$iHash = "blake2s256"
					Case "SHA256"
						$idHash = "SHA256"
						$iHash = "sha256"
					Case "SHA512_256"
						$idHash = "SHA512_256"
						$iHash = "sha512_256"
					Case "SHA512"
						$idHash = "SHA512"
						$iHash = "sha512"
					Case "SM3"
						$idHash = "SM3"
						$iHash = "sm3"
					Case "Streebog256"
						$idHash = "STREEBOG256"
						$iHash = "streebog256"
					Case "Streebog512"
						$idHash = "STREEBOG512"
						$iHash = "streebog512"
					Case "CubeHash"
						$idHash = "CUBEHASH"
						$iHash = "cubehash"
					Case "Whirlpool"
						$idHash = "WHIRLPOOL"
						$iHash = "whirlpool"
					Case "SHA3_256"
						$idHash = "SHA3_256"
						$iHash = "sha3_256"
					Case "SHA3_512"
						$idHash = "SHA3_512"
						$iHash = "sha3_512"
					Case "RIPEMD128"
						$idHash = "RMD128"
						$iHash = "rmd128"
					Case "RIPEMD160"
						$idHash = "RMD160"
						$iHash = "rmd160"
					Case "RIPEMD256"
						$idHash = "RMD256"
						$iHash = "rmd256"
					Case "GOST94-CryptoPro"
						$idHash = "GOST94"
						$iHash = "gost94"
					Case "LSH256"
						$idHash = "LSH256"
						$iHash = "lsh256"
					Case "LSH512_256"
						$idHash = "LSH512_256"
						$iHash = "lsh512_256"
					Case "LSH512"
						$idHash = "LSH512"
						$iHash = "lsh512"
					Case "Keccak256"
						$idHash = "KECCAK256"
						$iHash = "keccak256"
					Case "Keccak512"
						$idHash = "KECCAK512"
						$iHash = "keccak512"
					Case "Skein256"
						$idHash = "SKEIN256"
						$iHash = "skein256"
					Case "Skein512_256"
						$idHash = "SKEIN512_256"
						$iHash = "skein512_256"
					Case "Skein512"
						$idHash = "SKEIN512"
						$iHash = "skein512"
					Case "SipHash"
						$idHash = "SIPHASH"
						$iHash = "siphash"
					Case "Poly1305"
						$idHash = "POLY1305"
						$iHash = "poly1305"
					Case "Tiger"
						$idHash = "TIGER"
						$iHash = "tiger"
					Case "Groestl"
						$idHash = "GROESTL"
						$iHash = "groestl"
					Case "JH"
						$idHash = "JH"
						$iHash = "jh"
				EndSwitch
				Select
					Case GUICtrlRead($Radio5) = $GUI_CHECKED
						$radioval = "File"
					Case GUICtrlRead($Radio6) = $GUI_CHECKED
						$radioval = "String"
				EndSelect
				Global $sRead = GUICtrlRead($Edit17)
				Global $rRead = GUICtrlRead($Edit18)
				Global $xRead = GUICtrlRead($Edit16)
				Global $sFile = GUICtrlRead($Input5)
				If $radioval = "File" Then
					If GUICtrlRead($Checkbox2) = $GUI_CHECKED Then
						$CMD = "roottk -mac hmac -md " & $iHash & " -key """ & $rRead & """ -signature " & $xRead & " < " & $sFile & " > " & @TempDir & "Digest.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
						Local $sFileRead = FileRead(@TempDir & "Digest.txt")
						MsgBox($MB_SYSTEMMODAL, "", "Digest Verification:" & @CRLF & $sFileRead)
						FileDelete(@TempDir & "Digest.txt")
					Else
						$CMD = "roottk -digest - -md " & $iHash & " < """ & $sFile & """ -key """ & $rRead & """ > " & @TempDir & "Digest.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
						$Result = FileRead(@TempDir & "Digest.txt")
						If $Result = $xRead Then
							MsgBox($MB_SYSTEMMODAL, "", "Signature Verification:" & @CRLF & "true")
						Else
							MsgBox($MB_SYSTEMMODAL, "", "Signature Verification:" & @CRLF & "false")
						EndIf
						FileDelete(@TempDir & "Digest.txt")
					EndIf
				ElseIf $radioval = "String" Then
					If GUICtrlRead($Checkbox2) = $GUI_CHECKED Then
						$CMD = "busybox echo -n " & $sRead & " | roottk -mac hmac -md " & $iHash & " -key """ & $rRead & """ -signature " & $xRead & " > " & @TempDir & "Digest.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
						Local $sFileRead = FileRead(@TempDir & "Digest.txt")
						MsgBox($MB_SYSTEMMODAL, "", "Digest Verification:" & @CRLF & $sFileRead)
						FileDelete(@TempDir & "Digest.txt")
					Else
						$CMD = "busybox echo -n " & $sRead & " | roottk -digest - -md " & $iHash & " -key """ & $rRead & """ > " & @TempDir & "Digest.txt"
						RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
						$Result = FileRead(@TempDir & "Digest.txt")
						If $Result = $xRead Then
							MsgBox($MB_SYSTEMMODAL, "", "Digest Verification:" & @CRLF & "true")
						Else
							MsgBox($MB_SYSTEMMODAL, "", "Digest Verification:" & @CRLF & "false")
						EndIf
						FileDelete(@TempDir & "Digest.txt")
					EndIf
				EndIf

			Case $Button32
				ClipPut(GUICtrlRead($Edit16))

			Case $Button33
				Local $sData = ClipGet()
				GUICtrlSetData($Edit16, $sData)

			Case $Button36
				$length = 256
				Switch GUICtrlRead($Combo5)
					Case "BLAKE2s128"
						$length = 128
					Case "BLAKE2s256"
						If GUICtrlRead($Checkbox2) = $GUI_CHECKED Then
							$length = 256
						Else
							$length = 128
						EndIf
				EndSwitch
				$CMD = "roottk -rand -bits " & $length & " > " & @TempDir & "Key.txt"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$Key = FileRead(@TempDir & "Key.txt")
				$LineFeedStrip = StringReplace($Key, @LF, "")
				GUICtrlSetData($Edit18, $LineFeedStrip)
;				FileDelete(@TempDir & "Key.txt")
				$CMD = "roottk -shred " & @TempDir & "Key.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button39 ; KDF
				Switch GUICtrlRead($Combo5)
					Case "BLAKE2b256"
						$idHash = "BLAKE2B256"
						$iHash = "blake2b256"
					Case "BLAKE2b512"
						$idHash = "BLAKE2B512"
						$iHash = "blake2b512"
					Case "BLAKE2s256"
						$idHash = "BLAKE2S256"
						$iHash = "blake2s256"
					Case "SHA256"
						$idHash = "SHA256"
						$iHash = "sha256"
					Case "SHA512_256"
						$idHash = "SHA512_256"
						$iHash = "sha512_256"
					Case "SHA512"
						$idHash = "SHA512"
						$iHash = "sha512"
					Case "SM3"
						$idHash = "SM3"
						$iHash = "sm3"
					Case "Streebog256"
						$idHash = "STREEBOG256"
						$iHash = "streebog256"
					Case "Streebog512"
						$idHash = "STREEBOG512"
						$iHash = "streebog512"
					Case "CubeHash"
						$idHash = "CUBEHASH"
						$iHash = "cubehash"
					Case "Whirlpool"
						$idHash = "WHIRLPOOL"
						$iHash = "whirlpool"
					Case "SHA3_256"
						$idHash = "SHA3_256"
						$iHash = "sha3_256"
					Case "SHA3_512"
						$idHash = "SHA3_512"
						$iHash = "sha3_512"
					Case "RIPEMD128"
						$idHash = "RMD128"
						$iHash = "rmd128"
					Case "RIPEMD160"
						$idHash = "RMD160"
						$iHash = "rmd160"
					Case "RIPEMD256"
						$idHash = "RMD256"
						$iHash = "rmd256"
					Case "GOST94-CryptoPro"
						$idHash = "GOST94"
						$iHash = "gost94"
					Case "LSH256"
						$idHash = "LSH256"
						$iHash = "lsh256"
					Case "LSH512_256"
						$idHash = "LSH512_256"
						$iHash = "lsh512_256"
					Case "LSH512"
						$idHash = "LSH512"
						$iHash = "lsh512"
					Case "Keccak256"
						$idHash = "KECCAK256"
						$iHash = "keccak256"
					Case "Keccak512"
						$idHash = "KECCAK512"
						$iHash = "keccak512"
					Case "Skein256"
						$idHash = "SKEIN256"
						$iHash = "skein256"
					Case "Skein512_256"
						$idHash = "SKEIN512_256"
						$iHash = "skein512_256"
					Case "Skein512"
						$idHash = "SKEIN512"
						$iHash = "skein512"
					Case "Tiger"
						$idHash = "TIGER"
						$iHash = "tiger"
					Case "Groestl"
						$idHash = "GROESTL"
						$iHash = "groestl"
					Case "JH"
						$idHash = "JH"
						$iHash = "jh"
				EndSwitch
				Global $rRead = GUICtrlRead($Edit18)
				Global $xRead = GUICtrlRead($Input6)
				Global $yRead = GUICtrlRead($Input7)
				Global $iRead = GUICtrlRead($Input8)
				Global $bRead = GUICtrlRead($Combo6)
				If GUICtrlRead($Checkbox3) = $GUI_CHECKED Then
					$CMD = "roottk -kdf pbkdf2 -md " & $iHash & " -bits " & $bRead & " -key " & $rRead & " -salt " & $xRead & " -iter " & $iRead & " > " & @TempDir & "KDF.txt"
					RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
					$id = "MAC-" & $idHash
					$Result = FileRead(@TempDir & "KDF.txt")
					GUICtrlSetData($Edit19, $Result)
;					FileDelete("KDF.txt")
					$CMD = "roottk -shred " & @TempDir & "KDF.txt -iter 5"
					RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				Else
					$CMD = "roottk -kdf hkdf -md " & $iHash & " -bits " & $bRead & " -key " & $rRead & " -salt " & $xRead & " -info " & $yRead & " > " & @TempDir & "KDF.txt"
					RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
					$Result = FileRead(@TempDir & "KDF.txt")
					GUICtrlSetData($Edit19, $Result)
;					FileDelete("KDF.txt")
					$CMD = "roottk -shred " & @TempDir & "KDF.txt -iter 5"
					RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				EndIf

			Case $Button37
				$LineFeedStrip = StringReplace(GUICtrlRead($Edit19), @LF, "")
				ClipPut($LineFeedStrip)

			Case $Button40
				Global $sRead = GUICtrlRead($Edit20)
				Global $rRead = GUICtrlRead($Edit21)
				Global $xRead = GUICtrlRead($Edit16)
				Global $hRead = GUICtrlRead($Input10)
				Global $tRead = GUICtrlRead($Input11)
				Global $wRead = GUICtrlRead($Input12)
				Switch GUICtrlRead($Combo7)
					Case "ECDSA"
						$iAlgorithm = "ecdsa"
					Case "SM2"
						$iAlgorithm = "sm2"
					Case "Ed25519"
						$iAlgorithm = "ed25519"
					Case "GOST2012"
						$iAlgorithm = "gost2012"
				EndSwitch
				If GUICtrlRead($Combo7) = "GOST2012" Then
					$CMD = "busybox echo -n """ & $rRead & """ | gostls -tcp send -pub """ & $tRead & ":" & $wRead & """"
				Else
					$CMD = "busybox echo -n """ & $rRead & """ | roottk -tcp send -pub """ & $tRead & ":" & $wRead & """ -algorithm " & $iAlgorithm & ""
				EndIf
;				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				RunWait(@ComSpec & " /c " & $CMD, "", 6)

			Case $Button41
				Global $sRead = GUICtrlRead($Edit20)
				Global $rRead = GUICtrlRead($Edit21)
				Global $xRead = GUICtrlRead($Edit16)
				Global $hRead = GUICtrlRead($Input10)
				Global $tRead = GUICtrlRead($Input11)
				Global $wRead = GUICtrlRead($Input12)
				Switch GUICtrlRead($Combo7)
					Case "ECDSA"
						$iAlgorithm = "ecdsa"
					Case "SM2"
						$iAlgorithm = "sm2"
					Case "Ed25519"
						$iAlgorithm = "ed25519"
					Case "GOST2012"
						$iAlgorithm = "gost2012"
				EndSwitch
				If GUICtrlRead($Combo7) = "GOST2012" Then
					$CMD = "gostls -tcp dump -pub " & $hRead & " > dump.txt"
				Else
					$CMD = "roottk -tcp dump -pub " & $hRead & " -algorithm " & $iAlgorithm & " > dump.txt"
				EndIf
				RunWait(@ComSpec & " /c " & $CMD, "", 6)
				$Result = FileRead("dump.txt")
				GUICtrlSetData($Edit20, $Result)
;				FileDelete("dump.txt")
				$CMD = "roottk -shred " & @TempDir & "dump.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button42
				$CMD = "roottk -tcp ip > " & @TempDir & "ip.txt"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$Result = FileRead(@TempDir & "ip.txt")
				$LineFeedStrip = StringReplace($Result, @LF, "")
				GUICtrlSetData($Input9, $LineFeedStrip)
				FileDelete("ip.txt")

			Case $Button43
				ClipPut(GUICtrlRead($Edit20))

			Case $Button44
				Local $sData = ClipGet()
				GUICtrlSetData($Edit20, $sData)

			Case $Button45
				ClipPut(GUICtrlRead($Edit21))

			Case $Button46
				Local $sData = ClipGet()
				GUICtrlSetData($Edit21, $sData)

			Case $Button50
				Local $sFilePath = FileOpenDialog("Open a file", "", "All files (*.*)")
				If @error Then
					ContinueLoop
				EndIf
				GUICtrlSetData($Input13, $sFilePath)

			Case $Button51 ; Generate Secret for OMAC1
				Switch GUICtrlRead($Combo10)
					Case "MAC"
						$iCommand = "-mac"
					Case "CMAC"
						$iCommand = "-mac cmac"
					Case "PMAC"
						$iCommand = "-mac pmac"
				EndSwitch
				If GUICtrlRead($Combo10) = "CMAC" or GUICtrlRead($Combo10) = "PMAC" Then
					Switch GUICtrlRead($Combo11)
						Case "AES (Rijndael)"
							$iAlgorithm = "aes"
							$length = 128
						Case "Anubis"
							$iAlgorithm = "anubis"
							$length = 64
						Case "ARIA"
							$iAlgorithm = "aria"
							$length = 128
						Case "Serpent"
							$iAlgorithm = "serpent"
							$length = 128
						Case "Kuznechik"
							$iAlgorithm = "grasshopper"
							$length = 128
						Case "SEED"
							$iAlgorithm = "seed"
							$length = 128
						Case "Simon128"
							$iAlgorithm = "simon128"
							$length = 128
						Case "Speck128"
							$iAlgorithm = "speck128"
							$length = 128
						Case "Simon64"
							$iAlgorithm = "simon64"
							$length = 64
						Case "Speck64"
							$iAlgorithm = "speck64"
							$length = 64
						Case "SM4"
							$iAlgorithm = "sm4"
							$length = 64
						Case "Twofish"
							$iAlgorithm = "twofish"
							$length = 128
						Case "MISTY1"
							$iAlgorithm = "misty1"
							$length = 64
						Case "GOST89-CryptoPro"
							$iAlgorithm = "gost89"
							$length = 128
						Case "Magma"
							$iAlgorithm = "magma"
							$length = 128
						Case "Camellia"
							$iAlgorithm = "camellia"
							$length = 128
						Case "LEA"
							$iAlgorithm = "lea"
							$length = 128
						Case "HIGHT"
							$iAlgorithm = "hight"
							$length = 64
						Case "PRESENT"
							$iAlgorithm = "present"
							$length = 64
						Case "TWINE"
							$iAlgorithm = "twine"
							$length = 64
					EndSwitch
				EndIf
				If GUICtrlRead($Combo10) = "MAC" Then
					Switch GUICtrlRead($Combo9)
						Case "ZUC-128"
							$iAlgorithm = "eia128"
							$length = 128
							$iv = 128
						Case "ZUC-256 32-bit"
							$iAlgorithm = "eia256"
							$length = 256
							$iv = 184
						Case "ZUC-256 64-bit"
							$iAlgorithm = "eia256"
							$length = 256
							$iv = 184
						Case "ZUC-256 128-bit"
							$iAlgorithm = "eia256"
							$length = 256
							$iv = 184
						Case "Chaskey"
							$iAlgorithm = "chaskey"
							$length = 64
							$iv = 0
						Case "Poly1305"
							$iAlgorithm = "poly1305"
							$length = 128
							$iv = 0
						Case "SipHash128"
							$iAlgorithm = "siphash"
							$length = 128
							$iv = 0
						Case "SipHash64"
							$iAlgorithm = "siphash64"
							$length = 128
							$iv = 0
						Case "Snow3G"
							$iAlgorithm = "uia2"
							$length = 128
							$iv = 0
						Case "GOST-MAC 32-bit"
							$iAlgorithm = "gost"
							$length = 128
							$iv = 64
						Case "GOST-MAC 64-bit"
							$iAlgorithm = "gost"
							$length = 128
							$iv = 64
					EndSwitch
				EndIf
				$CMD = "roottk -rand -bits " & $length & " > " & @TempDir & "Key.txt"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$Key = FileRead(@TempDir & "Key.txt")
				$LineFeedStrip = StringReplace($Key, @LF, "")
				GUICtrlSetData($Edit22, $LineFeedStrip)
;				FileDelete(@TempDir & "Key.txt")
				$CMD = "roottk -shred " & @TempDir & "Key.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button54 ; Generate IV
				Switch GUICtrlRead($Combo10)
					Case "MAC"
						$iCommand = "-mac"
					Case "CMAC"
						$iCommand = "-mac cmac"
					Case "PMAC"
						$iCommand = "-mac pmac"
				EndSwitch
				If GUICtrlRead($Combo10) = "CMAC" or GUICtrlRead($Combo10) = "PMAC" Then
					Switch GUICtrlRead($Combo11)
						Case "AES (Rijndael)"
							$iAlgorithm = "aes"
							$length = 128
							$iv = 0
						Case "Anubis"
							$iAlgorithm = "anubis"
							$length = 64
							$iv = 0
						Case "ARIA"
							$iAlgorithm = "aria"
							$length = 128
							$iv = 0
						Case "Serpent"
							$iAlgorithm = "serpent"
							$length = 128
							$iv = 0
						Case "Kuznechik"
							$iAlgorithm = "grasshopper"
							$length = 128
							$iv = 0
						Case "SEED"
							$iAlgorithm = "seed"
							$length = 128
							$iv = 0
						Case "Simon128"
							$iAlgorithm = "simon128"
							$length = 128
							$iv = 0
						Case "Speck128"
							$iAlgorithm = "speck128"
							$length = 128
							$iv = 0
						Case "Simon64"
							$iAlgorithm = "simon64"
							$length = 64
							$iv = 0
						Case "Speck64"
							$iAlgorithm = "speck64"
							$length = 64
							$iv = 0
						Case "SM4"
							$iAlgorithm = "sm4"
							$length = 64
							$iv = 0
						Case "Twofish"
							$iAlgorithm = "twofish"
							$length = 128
							$iv = 0
						Case "MISTY1"
							$iAlgorithm = "misty1"
							$length = 64
							$iv = 0
						Case "GOST89-CryptoPro"
							$iAlgorithm = "gost89"
							$length = 128
							$iv = 0
						Case "Magma"
							$iAlgorithm = "magma"
							$length = 128
							$iv = 0
						Case "Camellia"
							$iAlgorithm = "camellia"
							$length = 128
							$iv = 0
						Case "LEA"
							$iAlgorithm = "lea"
							$length = 128
							$iv = 0
						Case "HIGHT"
							$iAlgorithm = "hight"
							$length = 64
							$iv = 0
						Case "PRESENT"
							$iAlgorithm = "present"
							$length = 64
							$iv = 0
						Case "TWINE"
							$iAlgorithm = "twine"
							$length = 64
							$iv = 0
					EndSwitch
				EndIf
				If GUICtrlRead($Combo10) = "MAC" Then
					Switch GUICtrlRead($Combo9)
						Case "ZUC-128"
							$iAlgorithm = "eia128"
							$length = 128
							$iv = 128
						Case "ZUC-256 32-bit"
							$iAlgorithm = "eia256"
							$length = 256
							$iv = 184
						Case "ZUC-256 64-bit"
							$iAlgorithm = "eia256"
							$length = 256
							$iv = 184
						Case "ZUC-256 128-bit"
							$iAlgorithm = "eia256"
							$length = 256
							$iv = 184
						Case "Chaskey"
							$iAlgorithm = "chaskey"
							$length = 64
							$iv = 0
						Case "Poly1305"
							$iAlgorithm = "poly1305"
							$length = 128
							$iv = 0
						Case "SipHash128"
							$iAlgorithm = "siphash"
							$length = 128
							$iv = 0
						Case "SipHash64"
							$iAlgorithm = "siphash64"
							$length = 128
							$iv = 0
						Case "Snow3G"
							$iAlgorithm = "uia2"
							$length = 128
							$iv = 0
						Case "GOST-MAC 32-bit"
							$iAlgorithm = "gost"
							$length = 128
							$iv = 64
						Case "GOST-MAC 64-bit"
							$iAlgorithm = "gost"
							$length = 128
							$iv = 64
					EndSwitch
				EndIf
				$CMD = "roottk -rand -bits " & $iv & " > " & @TempDir & "Key.txt"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$Key = FileRead(@TempDir & "Key.txt")
				$LineFeedStrip = StringReplace($Key, @LF, "")
				GUICtrlSetData($Edit24, $LineFeedStrip)
;				FileDelete(@TempDir & "Key.txt")
				$CMD = "roottk -shred " & @TempDir & "Key.txt -iter 5"
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)

			Case $Button47 ; Generate MAC
				Global $sRead = GUICtrlRead($Edit13)
				Global $rRead = GUICtrlRead($Edit22)
				Global $xRead = GUICtrlRead($Edit24)
				Global $yRead = GUICtrlRead($Edit23)
				Global $sFile = GUICtrlRead($Input13)
				Switch GUICtrlRead($Combo10)
					Case "MAC"
						$iCommand = "-mac"
					Case "CMAC"
						$iCommand = "-mac cmac -cipher"
					Case "PMAC"
						$iCommand = "-mac pmac -cipher"
				EndSwitch
				If GUICtrlRead($Combo10) = "CMAC" or GUICtrlRead($Combo10) = "PMAC" Then
					Switch GUICtrlRead($Combo11)
						Case "AES (Rijndael)"
							$iAlgorithm = "aes"
							$idCipher = "AES"
						Case "Anubis"
							$iAlgorithm = "anubis"
							$idCipher = "ANUBIS"
						Case "ARIA"
							$iAlgorithm = "aria"
							$idCipher = "ARIA"
						Case "Serpent"
							$iAlgorithm = "serpent"
							$idCipher = "SERPENT"
						Case "Kuznechik"
							$iAlgorithm = "grasshopper"
							$idCipher = "GRASSHOPPER"
						Case "SEED"
							$iAlgorithm = "seed"
							$idCipher = "SEED"
						Case "Simon128"
							$iAlgorithm = "simon128"
							$idCipher = "SIMON128"
						Case "Speck128"
							$iAlgorithm = "speck128"
							$idCipher = "SPECK128"
						Case "Simon64"
							$iAlgorithm = "simon64"
							$idCipher = "SIMON64"
						Case "Speck64"
							$iAlgorithm = "speck64"
							$idCipher = "SPECK64"
						Case "SM4"
							$iAlgorithm = "sm4"
							$idCipher = "SM4"
						Case "Twofish"
							$iAlgorithm = "twofish"
							$idCipher = "TWOFISH"
						Case "MISTY1"
							$iAlgorithm = "misty1"
							$idCipher = "MISTY1"
						Case "GOST89-CryptoPro"
							$iAlgorithm = "gost89"
							$idCipher = "GOST89"
						Case "Magma"
							$iAlgorithm = "magma"
							$idCipher = "MAGMA"
						Case "Camellia"
							$iAlgorithm = "camellia"
							$idCipher = "CAMELLIA"
						Case "LEA"
							$iAlgorithm = "lea"
							$idCipher = "LEA"
						Case "HIGHT"
							$iAlgorithm = "hight"
							$idCipher = "HIGHT"
						Case "PRESENT"
							$iAlgorithm = "present"
							$idCipher = "PRESENT"
						Case "TWINE"
							$iAlgorithm = "twine"
							$idCipher = "TWINE"
					EndSwitch
				EndIf
				If GUICtrlRead($Combo10) = "MAC" Then
					Switch GUICtrlRead($Combo9)
						Case "ZUC-128"
							$iAlgorithm = "eia128"
							$idCipher = "EIA128"
						Case "ZUC-256 32-bit"
							$iAlgorithm = "eia256 -bits 32"
							$idCipher = "EIA256"
						Case "ZUC-256 64-bit"
							$iAlgorithm = "eia256 -bits 64"
							$idCipher = "EIA256"
						Case "ZUC-256 128-bit"
							$iAlgorithm = "eia256"
							$idCipher = "EIA256"
						Case "Chaskey"
							$iAlgorithm = "chaskey"
							$idCipher = "CHASKEY"
						Case "Poly1305"
							$iAlgorithm = "poly1305"
							$idCipher = "POLY1305"
						Case "SipHash128"
							$iAlgorithm = "siphash"
							$idCipher = "SIPHASH128"
						Case "SipHash64"
							$iAlgorithm = "siphash64"
							$idCipher = "SIPHASH64"
						Case "Snow3G"
							$iAlgorithm = "uia2"
							$idCipher = "UIA2"
						Case "GOST-MAC 32-bit"
							$iAlgorithm = "gost"
							$idCipher = "GOST"
						Case "GOST-MAC 64-bit"
							$iAlgorithm = "gost -bits 64"
							$idCipher = "GOST"
					EndSwitch
				EndIf
				Select
					Case GUICtrlRead($Radio7) = $GUI_CHECKED
						$radioval = "File"
					Case GUICtrlRead($Radio8) = $GUI_CHECKED
						$radioval = "String"
				EndSelect
				$id = "MAC-" & $idCipher
				If $radioval = "File" Then
					$CMD = "echo [MAC] > " & @TempDir & "MAC.txt & roottk " & $iCommand & " " & $iAlgorithm & " -key """ & $rRead & """ -iv """ & $xRead & """ < " & $sFile & " >> " & @TempDir & "MAC.txt"
				Else
					$CMD = "echo [MAC] > " & @TempDir & "MAC.txt & busybox echo -n """ & $sRead & """ |roottk " & $iCommand & " " & $iAlgorithm & " -key """ & $rRead & """ -iv """ & $xRead & """ >> " & @TempDir & "MAC.txt"
				EndIf
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				$MAC = IniRead(@TempDir & "MAC.txt", "MAC", $id, "Error.")
				GUICtrlSetData($Edit23, $MAC)
				FileDelete(@TempDir & "MAC.txt")

			Case $Button48
				Global $sRead = GUICtrlRead($Edit13)
				Global $rRead = GUICtrlRead($Edit22)
				Global $xRead = GUICtrlRead($Edit24)
				Global $yRead = GUICtrlRead($Edit23)
				Global $sFile = GUICtrlRead($Input13)
				Switch GUICtrlRead($Combo10)
					Case "MAC"
						$iCommand = "-mac"
					Case "CMAC"
						$iCommand = "-mac cmac -cipher"
					Case "PMAC"
						$iCommand = "-mac pmac -cipher"
				EndSwitch
				If GUICtrlRead($Combo10) = "CMAC" or GUICtrlRead($Combo10) = "PMAC" Then
					Switch GUICtrlRead($Combo11)
						Case "AES (Rijndael)"
							$iAlgorithm = "aes"
						Case "Anubis"
							$iAlgorithm = "anubis"
						Case "ARIA"
							$iAlgorithm = "aria"
						Case "Serpent"
							$iAlgorithm = "serpent"
						Case "Kuznechik"
							$iAlgorithm = "grasshopper"
						Case "SEED"
							$iAlgorithm = "seed"
						Case "Simon128"
							$iAlgorithm = "simon128"
						Case "Speck128"
							$iAlgorithm = "speck128"
						Case "Simon64"
							$iAlgorithm = "simon64"
						Case "Speck64"
							$iAlgorithm = "speck64"
						Case "SM4"
							$iAlgorithm = "sm4"
						Case "Twofish"
							$iAlgorithm = "twofish"
						Case "MISTY1"
							$iAlgorithm = "misty1"
						Case "GOST89-CryptoPro"
							$iAlgorithm = "gost89"
						Case "Magma"
							$iAlgorithm = "magma"
						Case "Camellia"
							$iAlgorithm = "camellia"
						Case "LEA"
							$iAlgorithm = "lea"
						Case "HIGHT"
							$iAlgorithm = "hight"
						Case "PRESENT"
							$iAlgorithm = "present"
						Case "TWINE"
							$iAlgorithm = "twine"
					EndSwitch
				EndIf
				If GUICtrlRead($Combo10) = "MAC" Then
					Switch GUICtrlRead($Combo9)
						Case "ZUC-128"
							$iAlgorithm = "eia128"
						Case "ZUC-256 32-bit"
							$iAlgorithm = "eia256 -bits 32"
						Case "ZUC-256 64-bit"
							$iAlgorithm = "eia256 -bits 64"
						Case "ZUC-256 128-bit"
							$iAlgorithm = "eia256"
						Case "Chaskey"
							$iAlgorithm = "chaskey"
						Case "Poly1305"
							$iAlgorithm = "poly1305"
						Case "SipHash128"
							$iAlgorithm = "siphash"
						Case "SipHash64"
							$iAlgorithm = "siphash64"
						Case "Snow3G"
							$iAlgorithm = "uia2"
						Case "GOST-MAC 32-bit"
							$iAlgorithm = "gost"
						Case "GOST-MAC 64-bit"
							$iAlgorithm = "gost -bits 64"
					EndSwitch
				EndIf
				Select
					Case GUICtrlRead($Radio7) = $GUI_CHECKED
						$radioval = "File"
					Case GUICtrlRead($Radio8) = $GUI_CHECKED
						$radioval = "String"
				EndSelect
				If $radioval = "File" Then
					$CMD = "roottk " & $iCommand & " " & $iAlgorithm & " -key """ & $rRead & """ -iv """ & $xRead & """ -signature """ & $yRead & """ < " & $sFile & " > " & @TempDir & "Check.txt"
				Else
					$CMD = "busybox echo -n """ & $sRead & """ |roottk " & $iCommand & " " & $iAlgorithm & " -key """ & $rRead & """ -iv """ & $xRead & """ -signature """ & $yRead & """ > " & @TempDir & "Check.txt"
				EndIf
				RunWait(@ComSpec & " /c " & $CMD, "", @SW_HIDE, 6)
				Local $sFileRead = FileRead(@TempDir & "Check.txt")
				MsgBox($MB_SYSTEMMODAL, "", "MAC Verification:" & @CRLF & $sFileRead)
				FileDelete(@TempDir & "Check.txt")
		EndSwitch
	WEnd
EndFunc   ;==>Main

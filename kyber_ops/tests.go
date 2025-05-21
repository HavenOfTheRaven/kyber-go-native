/*Copyright (c) 2025 Haven F.C. Johnson under the MIT license
The kyber algorithm has a license that can be found in the file titled "nist-pqc-license-summary-and-excerpts.pdf"

Go port of the kyber post quantum encryption algorithm laid out by the NIST round 3 package that can be found by following the link below:
https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022

This file contains code used for the test files in the kyber implementations: kyber_512,kyber_768,kyber_1024
*/
package kyber_ops

import(
	"encoding/hex"
	"errors"
)

func Upper(input string)string{
	temp_data:=[]byte(input)
	for i,char:=range temp_data{
		if char>96{
			temp_data[i]-=32
		}
	}
	return string(temp_data)
}

func Compare_Keys(str string,sk,pk,ct,ss_enc,ss_dec []byte,len_pk,len_sk,len_ct uint)(curpos uint,err error){
	var temp_len uint
	temp_len=len_pk*2
	if Upper(hex.EncodeToString(pk[:]))!=str[:temp_len]{
		err=errors.New("Public key does not match test file")
		return
	}
	temp_len+=6
	curpos=temp_len+len_sk*2
	if Upper(hex.EncodeToString(sk[:]))!=str[temp_len:curpos]{
		err=errors.New("Secret key does not match test file")
		return
	}
	temp_len=curpos+6
	curpos=temp_len+len_ct*2
	if Upper(hex.EncodeToString(ct[:]))!=str[temp_len:curpos]{
		err=errors.New("Ciphertext does not match test file")
		return
	}
	temp_len=curpos+6
	curpos=temp_len+64
	if Upper(hex.EncodeToString(ss_dec))!=str[temp_len:curpos]||Upper(hex.EncodeToString(ss_enc))!=str[temp_len:curpos]{
		err=errors.New("Shared key does not match test file")
		return
	}
	return
}

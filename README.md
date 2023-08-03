# kyber-go-native

Native Go implementation of the kyber post-quantum key exchange encryption scheme, more information can be found here: https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022

example:
```
package main

import(
	"fmt"
	"github.com/Tracy-Tzu/kyber-go-native/kyber_768"
)

func main(){
	sk:=kyber_768.Keygen()
	pk_bytes:=sk.Pk_Bytes[:]
	pk,err:=kyber_768.Bytes_to_Pk(pk_bytes)
	if err!=nil{
		fmt.Println(err)
	}
	ct,ss_enc:=pk.Enc(32)
	ss_dec,err:=sk.Dec(ct[:],32)
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Println(ss_dec)
	fmt.Println(ss_enc)
}
```

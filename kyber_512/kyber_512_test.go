/*Copyright (c) 2023 Tracy-Tzu under the MIT license
The kyber algorithm has a license that can be found in the file titled "nist-pqc-license-summary-and-excerpts.pdf"

Go port of the kyber post quantum encryption algorithm laid out by the NIST round 3 package that can be found by following the link below:
https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022

This file contains code to run tests and benchmarks on kyber_512 and kyber_512_90s
*/
package kyber_512

import(
	"github.com/Tracy-Tzu/kyber-go-native/kyber_ops"
	"testing"
	"os"
)

func Test_kyber512(t *testing.T){
	var curpos,temp_len uint
	data,err:=os.ReadFile("kyber512-kat.rsp")
	if err!=nil{
		t.Fatal(err)
	}
	test_string:=string(data)
	curpos=29
	for count:=0;count!=100;count++{
		temp_len,err=kyber_ops.Init_Seed(test_string[curpos:])
		if err!=nil{
			t.Fatal(err)
		}
		curpos+=temp_len
		sk:=Keygen()
		pk,err:=Bytes_to_Pk(sk.Pk_Bytes[:])
		if err!=nil{
			t.Fatal(err)
		}
		ct,ss_enc:=pk.Enc(32)
		ss_dec,err:=sk.Dec(ct[:],32)
		if err!=nil{
			t.Fatal(err)
		}
		temp_sk_data:=sk.To_Bytes()
		temp_len,err=kyber_ops.Compare_Keys(test_string[curpos:],temp_sk_data[:],sk.Pk_Bytes[:],ct[:],ss_enc,ss_dec,pk_512_len,cc_sk_512_len,ciphertext_512_len)
		if err!=nil{
			t.Fatal(err)
		}
		curpos+=temp_len
		if count>8{
			curpos+=20
			continue
		}
		curpos+=19
	}
}

func Test_kyber512_90s(t *testing.T){
	var curpos,temp_len uint
	data,err:=os.ReadFile("kyber512_90s-kat.rsp")
	if err!=nil{
		t.Fatal(err)
	}
	test_string:=string(data)
	curpos=33
	for count:=0;count!=100;count++{
		temp_len,err=kyber_ops.Init_Seed(test_string[curpos:])
		if err!=nil{
			t.Fatal(err)
		}
		curpos+=temp_len
		sk:=Keygen_90s()
		pk,err:=Bytes_to_Pk_90s(sk.Pk_Bytes[:])
		if err!=nil{
			t.Fatal(err)
		}
		ct,ss_enc:=pk.Enc()
		ss_dec,err:=sk.Dec(ct[:])
		if err!=nil{
			t.Fatal(err)
		}
		temp_sk_data:=sk.To_Bytes()
		temp_len,err=kyber_ops.Compare_Keys(test_string[curpos:],temp_sk_data[:],sk.Pk_Bytes[:],ct[:],ss_enc[:],ss_dec[:],pk_512_len,cc_sk_512_len,ciphertext_512_len)
		if err!=nil{
			t.Fatal(err)
		}
		curpos+=temp_len
		if count>8{
			curpos+=20
			continue
		}
		curpos+=19
	}
}

var(
	bench_key_512 *sk_512
	bench_key_512_90s *sk_512_90s
	bench_ct_512 [ciphertext_512_len]byte
	bench_ss_90s [32]byte
	bench_ss []byte
)

func Benchmark_Keygen_512(b *testing.B){
	for i:=0;i<b.N;i++{
		bench_key_512=Keygen()
	}
}

func Benchmark_Keygen_512_90s(b *testing.B){
	for i:=0;i<b.N;i++{
		bench_key_512_90s=Keygen_90s()
	}
}

func Benchmark_Enc_512(b *testing.B){
	temp_pk,_:=Bytes_to_Pk(bench_key_512.Pk_Bytes[:])
	for i:=0;i<b.N;i++{
		bench_ct_512,bench_ss=temp_pk.Enc(32)
	}
}

func Benchmark_Enc_512_90s(b *testing.B){
	temp_pk,_:=Bytes_to_Pk_90s(bench_key_512.Pk_Bytes[:])
	for i:=0;i<b.N;i++{
		bench_ct_512,bench_ss_90s=temp_pk.Enc()
	}
}

func Benchmark_Dec_512(b *testing.B){
	for i:=0;i<b.N;i++{
		bench_ss,_=bench_key_512.Dec(bench_ct_512[:],32)
	}
}

func Benchmark_Dec_512_90s(b *testing.B){
	for i:=0;i<b.N;i++{
		bench_ss_90s,_=bench_key_512_90s.Dec(bench_ct_512[:])
	}
}

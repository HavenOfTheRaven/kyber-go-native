/*Copyright (c) 2023 Tracy-Tzu under the MIT license
The kyber algorithm has a license that can be found in the file titled "nist-pqc-license-summary-and-excerpts.pdf"

Go port of the kyber post quantum encryption algorithm laid out by the NIST round 3 package that can be found by following the link below:
https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022

This file contains code to implement kyber_1024 and kyber_1024_90s
*/
package kyber_1024

import(
	"github.com/Tracy-Tzu/kyber-go-native/kyber_ops"
	"golang.org/x/crypto/sha3"
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
)

const k_1024,cp_sk_1024_len,pk_1024_len,cc_sk_1024_len,ciphertext_1024_len=4,12*k_1024*256/8,cp_sk_1024_len+32,cp_sk_1024_len*2+96,1568

type sk_1024 struct{
	Seed,z,h [32]byte
	sk,pk [4][256]int16
	Pk_Bytes [1568]byte
}

type pk_1024 struct{
	p [32]byte
	pk [4][256]int16
	Bytes [1568]byte
}

type sk_1024_90s struct{
	Seed,z,h [32]byte
	sk,pk [4][256]int16
	Pk_Bytes [1568]byte
}

type pk_1024_90s struct{
	p [32]byte
	pk [4][256]int16
	Bytes [1568]byte
}

func Bytes_to_Pk(data []byte)(pk *pk_1024,err error){
	if len(data)!=1568{
		err=errors.New("input data for Bytes_to_1024_Pk must be 1568 bytes long")
		return
	}
	pk=new(pk_1024)
	copy(pk.Bytes[:],data)
	copy(pk.p[:],data[1536:])
	kyber_ops.Decode_12(data,&pk.pk)
	return
}

func Bytes_to_Sk(data []byte)(sk *sk_1024,err error){
	var bytes32 [32]byte
	if len(data)!=3168{
		err=errors.New("input data for Bytes_to_1024_Sk must be 3168 bytes long")//redo this not to incude 1024
		return
	}
	sk=new(sk_1024)//seed is left alone
	kyber_ops.Decode_12(data,&sk.sk)
	copy(sk.Pk_Bytes[:],data[1536:])
	kyber_ops.Decode_12(sk.Pk_Bytes[:],&sk.pk)
	copy(bytes32[:],data[3104:])
	test32:=sha3.Sum256(sk.Pk_Bytes[:])
	if test32!=bytes32{
		err=errors.New("public key mismatch")
		return
	}
	copy(sk.z[:],data[3136:])
	return
}

func Bytes_to_Pk_90s(data []byte)(pk *pk_1024_90s,err error){
	if len(data)!=1568{
		err=errors.New("input data for Bytes_to_1024_Pk must be 1568 bytes long")
		return
	}
	pk=new(pk_1024_90s)
	copy(pk.Bytes[:],data)
	copy(pk.p[:],data[1536:])
	kyber_ops.Decode_12(data,&pk.pk)
	return
}

func Bytes_to_Sk_90s(data []byte)(sk *sk_1024_90s,err error){
	var bytes32 [32]byte
	if len(data)!=3168{
		err=errors.New("input data for Bytes_to_1024_Sk must be 3168 bytes long")
		return
	}
	sk=new(sk_1024_90s)//seed is left alone
	kyber_ops.Decode_12(data,&sk.sk)
	copy(sk.Pk_Bytes[:],data[1536:])
	kyber_ops.Decode_12(sk.Pk_Bytes[:],&sk.pk)
	copy(bytes32[:],data[3104:])
	test32:=sha256.Sum256(sk.Pk_Bytes[:])
	if test32!=bytes32{
		err=errors.New("public key mismatch")
		return
	}
	copy(sk.z[:],data[3136:])
	return
}

func Keygen()*sk_1024{
	keys:=new(sk_1024)
	kyber_ops.Read_RNG(keys.Seed[:])
	seed_keygen_1024(keys)
	return keys
}

func (sk *sk_1024)To_Bytes()(data [cc_sk_1024_len]byte){
	kyber_ops.Encode_12(&sk.sk,data[:])
	copy(data[cp_sk_1024_len:],sk.Pk_Bytes[:])
	copy(data[cc_sk_1024_len-64:],sk.h[:])
	copy(data[cc_sk_1024_len-32:],sk.z[:])
	return
}

func (sk *sk_1024_90s)To_Bytes()(data [cc_sk_1024_len]byte){
	kyber_ops.Encode_12(&sk.sk,data[:])
	copy(data[cp_sk_1024_len:],sk.Pk_Bytes[:])
	copy(data[cc_sk_1024_len-64:],sk.h[:])
	copy(data[cc_sk_1024_len-32:],sk.z[:])
	return
}

func Seed_to_Keys(seed [32]byte)(*sk_1024,error){
	if seed==[32]byte{}{
		return nil,errors.New("keys can not be recovered, nil seed")
	}
	keys:=new(sk_1024)
	keys.Seed=seed
	seed_keygen_1024(keys)
	return keys,nil
}

func seed_keygen_1024(keys *sk_1024){
	var(
		i,j uint8
		A [k_1024][k_1024][256]int16
		e [k_1024][256]int16
		t [256]int16
		bytes128 [128]byte
		o [33]byte
		p [34]byte
	)
	xof:=sha3.NewShake128()
	shake:=sha3.NewShake256()
	temp:=sha3.Sum512(keys.Seed[:])
	copy(p[:],temp[:32])
	copy(o[:],temp[32:])
	for i=0;i<k_1024;i++{
		p[33]=i
		for j=0;j<k_1024;j++{
			p[32]=j
			xof.Write(p[:])
			kyber_ops.Parse_shake(&A[i][j],xof)
			xof.Reset()
		}
	}
	kyber_ops.CBD2_cycle_shake(&keys.sk,&bytes128,&o,shake)
	kyber_ops.CBD2_cycle_shake(&e,&bytes128,&o,shake)
	kyber_ops.NTT_vec(&keys.sk)
	kyber_ops.NTT_vec(&e)
	for i=0;i<k_1024;i++{
		kyber_ops.Mul_matrix(&keys.sk,&A[i],&keys.pk[i],&t)
		kyber_ops.Mont_poly(&keys.pk[i])
	}
	kyber_ops.Add_vec(&keys.pk,&e,&keys.pk)
	kyber_ops.Mod_vec(&keys.pk)
	kyber_ops.CSUBQ_vec(&keys.sk)
	kyber_ops.CSUBQ_vec(&keys.pk)
	kyber_ops.Encode_12(&keys.pk,keys.Pk_Bytes[:])
	copy(keys.Pk_Bytes[cp_sk_1024_len:],p[:])
	kyber_ops.Read_RNG(keys.z[:])
	keys.h=sha3.Sum256(keys.Pk_Bytes[:])
}

func cpapke_enc_1024(pk *[k_1024][256]int16,m [32]byte,temp_r,temp_p []byte)(c [ciphertext_1024_len]byte){
	var (
		i,j uint8
		A [k_1024][k_1024][256]int16
		s,e1,u [k_1024][256]int16
		e2,v,t [256]int16
		bytes128 [128]byte
		r [33]byte
		p [34]byte
	)
	copy(r[:],temp_r)
	copy(p[:],temp_p)
	xof:=sha3.NewShake128()
	shake:=sha3.NewShake256()
	for i=0;i<k_1024;i++{
		p[32]=i
		for j=0;j<k_1024;j++{
			p[33]=j
			xof.Write(p[:])
			kyber_ops.Parse_shake(&A[i][j],xof)
			xof.Reset()
		}
	}
	kyber_ops.CBD2_cycle_shake(&s,&bytes128,&r,shake)
	kyber_ops.CBD2_cycle_shake(&e1,&bytes128,&r,shake)
	shake.Write(r[:])
	shake.Read(bytes128[:])
	kyber_ops.CBD2(&bytes128,&e2)
	kyber_ops.NTT_vec(&s)
	for i=0;i<k_1024;i++{
		kyber_ops.Mul_matrix(&A[i],&s,&u[i],&t)
	}
	kyber_ops.Mul_matrix(pk,&s,&v,&t)
	for i=0;i<k_1024;i++{
		kyber_ops.Inv(&u[i])
	}
	kyber_ops.Inv(&v)
	kyber_ops.Add_vec(&e1,&u,&u)
	kyber_ops.Add_poly(&e2,&v,&v)
	kyber_ops.Decom_1(m[:],&e2)
	kyber_ops.Add_poly(&e2,&v,&v)
	kyber_ops.Mod_vec(&u)
	kyber_ops.Mod_poly(&v)
	kyber_ops.CSUBQ_vec(&u)
	kyber_ops.CSUBQ_poly(&v)
	kyber_ops.Com_11(&u,c[:])
	kyber_ops.Com_5(&v,c[ciphertext_1024_len-160:])
	return
}

func cpapke_dec_1024(sk *[k_1024][256]int16,c []byte)(m [32]byte){
	var u [k_1024][256]int16
	var v,mp [256]int16
	kyber_ops.Decom_11(c,&u)
	kyber_ops.NTT_vec(&u)
	kyber_ops.Mul_matrix(sk,&u,&mp,&v)
	kyber_ops.Inv(&mp)
	kyber_ops.Decom_5(c[ciphertext_1024_len-160:],&v)
	kyber_ops.Sub_poly(&v,&mp,&mp)
	kyber_ops.Mod_poly(&mp)
	kyber_ops.Com_1(&mp,m[:])
	return
}

func (pk *pk_1024)Enc(Shared_key_length int)(c [ciphertext_1024_len]byte,K []byte){
	var m,temp [32]byte
	kyber_ops.Read_RNG(m[:])
	m=sha3.Sum256(m[:])
	G:=sha3.New512()
	G.Write(m[:])
	temp=sha3.Sum256(pk.Bytes[:])
	G.Write(temp[:])
	Kr:=G.Sum(nil)
	c=cpapke_enc_1024(&pk.pk,m,Kr[32:],pk.p[:])
	KDF:=sha3.NewShake256()
	KDF.Write(Kr[:32])
	temp=sha3.Sum256(c[:])
	KDF.Write(temp[:])
	K=make([]byte,Shared_key_length)
	KDF.Read(K[:])
	return
}

func (sk *sk_1024)Dec(c []byte,Shared_key_length int)(K []byte,err error){
	if len(c)!=ciphertext_1024_len{
		err=errors.New("ciphertext must be 1568 bytes long")
		return
	}
	m:=cpapke_dec_1024(&sk.sk,c)
	G:=sha3.New512()
	G.Write(m[:])
	G.Write(sk.h[:])
	Kr:=G.Sum(nil)
	c_:=cpapke_enc_1024(&sk.pk,m,Kr[32:],sk.Pk_Bytes[pk_1024_len-32:])
 	KDF:=sha3.NewShake256()
	H:=sha3.New256()
	H.Write(c[:])
	if c_==*(*[1568]byte)(c){
		KDF.Write(H.Sum(Kr[:32]))
	}else{
		KDF.Write(H.Sum(sk.z[:]))
	}
	K=make([]byte,Shared_key_length)
	KDF.Read(K)
	return
}

func Keygen_90s()*sk_1024_90s{
	keys:=new(sk_1024_90s)
	kyber_ops.Read_RNG(keys.Seed[:])
	seed_keygen_1024_90s(keys)
	return keys
}

func Seed_to_Keys_90s(seed [32]byte)(*sk_1024_90s,error){
	if seed==[32]byte{}{
		return nil,errors.New("keys can not be recovered, nil seed")
	}
	keys:=new(sk_1024_90s)
	keys.Seed=seed
	seed_keygen_1024_90s(keys)
	return keys,nil
}

func seed_keygen_1024_90s(keys *sk_1024_90s){
	var(
		i,j uint8
		A [k_1024][k_1024][256]int16
		e [k_1024][256]int16
		t [256]int16
		bytes128 [128]byte
		iv [16]byte
	)
	temp:=sha512.Sum512(keys.Seed[:])
	xof,_:=aes.NewCipher(temp[:32])
	PRF,_:=aes.NewCipher(temp[32:])
	for i=0;i<k_1024;i++{
		iv[1]=i
		for j=0;j<k_1024;j++{
			iv[0]=j
			kyber_ops.Parse_aes(&A[i][j],xof,&iv)
			iv[12],iv[13],iv[14],iv[15]=0,0,0,0
		}
	}
	iv[0],iv[1]=0,0
	kyber_ops.CBD2_cycle_aes(&keys.sk,&bytes128,&iv,PRF)
	kyber_ops.CBD2_cycle_aes(&e,&bytes128,&iv,PRF)
	kyber_ops.NTT_vec(&keys.sk)
	kyber_ops.NTT_vec(&e)
	for i=0;i<k_1024;i++{
		kyber_ops.Mul_matrix(&keys.sk,&A[i],&keys.pk[i],&t)
		kyber_ops.Mont_poly(&keys.pk[i])
	}
	kyber_ops.Add_vec(&keys.pk,&e,&keys.pk)
	kyber_ops.Mod_vec(&keys.pk)
	kyber_ops.CSUBQ_vec(&keys.sk)
	kyber_ops.CSUBQ_vec(&keys.pk)
	kyber_ops.Encode_12(&keys.pk,keys.Pk_Bytes[:])
	copy(keys.Pk_Bytes[cp_sk_1024_len:],temp[:])
	kyber_ops.Read_RNG(keys.z[:])
	keys.h=sha256.Sum256(keys.Pk_Bytes[:])
}

func cpapke_enc_1024_90s(pk *[k_1024][256]int16,m [32]byte,temp_r,temp_p []byte)(c [ciphertext_1024_len]byte){
	var(
		i,j uint8
		A [k_1024][k_1024][256]int16
		s,e1,u [k_1024][256]int16
		e2,v,t [256]int16
		bytes128 [128]byte
		iv [16]byte
	)
	xof,_:=aes.NewCipher(temp_p)
	PRF,_:=aes.NewCipher(temp_r)
	for i=0;i<k_1024;i++{
		iv[0]=i
		for j=0;j<k_1024;j++{
			iv[1]=j
			kyber_ops.Parse_aes(&A[i][j],xof,&iv)
			iv[12],iv[13],iv[14],iv[15]=0,0,0,0
		}
	}
	iv[0],iv[1]=0,0
	kyber_ops.CBD2_cycle_aes(&s,&bytes128,&iv,PRF)
	kyber_ops.CBD2_cycle_aes(&e1,&bytes128,&iv,PRF)
	kyber_ops.AES_encrypt_128(PRF,&bytes128,&iv)
	kyber_ops.CBD2(&bytes128,&e2)
	kyber_ops.NTT_vec(&s)
	for i=0;i<k_1024;i++{
		kyber_ops.Mul_matrix(&A[i],&s,&u[i],&t)
	}
	kyber_ops.Mul_matrix(pk,&s,&v,&t)
	for i=0;i<k_1024;i++{
		kyber_ops.Inv(&u[i])
	}
	kyber_ops.Inv(&v)
	kyber_ops.Add_vec(&e1,&u,&u)
	kyber_ops.Add_poly(&e2,&v,&v)
	kyber_ops.Decom_1(m[:],&e2)
	kyber_ops.Add_poly(&e2,&v,&v)
	kyber_ops.Mod_vec(&u)
	kyber_ops.Mod_poly(&v)
	kyber_ops.CSUBQ_vec(&u)
	kyber_ops.CSUBQ_poly(&v)
	kyber_ops.Com_11(&u,c[:])
	kyber_ops.Com_5(&v,c[ciphertext_1024_len-160:])
	return
}

func (pk *pk_1024_90s)Enc()(c [ciphertext_1024_len]byte,K [32]byte){
	var m,temp [32]byte
	kyber_ops.Read_RNG(m[:])
	m=sha256.Sum256(m[:])
	G:=sha512.New()
	G.Write(m[:])
	temp=sha256.Sum256(pk.Bytes[:])
	G.Write(temp[:])
	Kr:=G.Sum(nil)
	c=cpapke_enc_1024_90s(&pk.pk,m,Kr[32:],pk.p[:])
	H:=sha256.New()
	H.Write(c[:])
	K=sha256.Sum256(H.Sum(Kr[:32]))
	return
}

func (sk *sk_1024_90s)Dec(c []byte)(K [32]byte,err error){
	if len(c)!=ciphertext_1024_len{
		err=errors.New("ciphertext must be 1568 bytes long")
		return
	}
	m:=cpapke_dec_1024(&sk.sk,c)
	G:=sha512.New()
	G.Write(m[:])
	G.Write(sk.h[:])
	Kr:=G.Sum(nil)
	c_:=cpapke_enc_1024_90s(&sk.pk,m,Kr[32:],sk.Pk_Bytes[pk_1024_len-32:])
	H:=sha256.New()
	H.Write(c[:])
	if c_==*(*[1568]byte)(c){
		K=sha256.Sum256(H.Sum(Kr[:32]))
	}else{
		K=sha256.Sum256(H.Sum(sk.z[:]))
	}
	return
}

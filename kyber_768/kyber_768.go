/*Copyright (c) 2023 Tracy-Tzu under the MIT license
The kyber algorithm has a license that can be found in the file titled "nist-pqc-license-summary-and-excerpts.pdf"

Go port of the kyber post quantum encryption algorithm laid out by the NIST round 3 package that can be found by following the link below:
https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022

This file contains code to implement kyber_768 and kyber_768_90s
*/
package kyber_768

import(
	"github.com/Tracy-Tzu/kyber-go-native/kyber_ops"
	"golang.org/x/crypto/sha3"
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
)

const k_768,cp_sk_768_len,pk_768_len,cc_sk_768_len,ciphertext_768_len=3,12*k_768*256/8,cp_sk_768_len+32,cp_sk_768_len*2+96,1088

type sk_768 struct{
	Seed,z,h [32]byte
	sk,pk [3][256]int16
	Pk_Bytes [1184]byte
}

type pk_768 struct{
	p [32]byte
	pk [3][256]int16
	Bytes [1184]byte
}

type sk_768_90s struct{
	Seed,z,h [32]byte
	sk,pk [3][256]int16
	Pk_Bytes [1184]byte
}

type pk_768_90s struct{
	p [32]byte
	pk [3][256]int16
	Bytes [1184]byte
}

func Bytes_to_Pk(data []byte)(pk *pk_768,err error){
	if len(data)!=1184{
		err=errors.New("input data for Bytes_to_768_Pk must be 1184 bytes long")
		return
	}
	pk=new(pk_768)
	copy(pk.Bytes[:],data)
	copy(pk.p[:],data[1152:])
	kyber_ops.Decode_12(data,&pk.pk)
	return
}

func Bytes_to_Sk(data []byte)(sk *sk_768,err error){
	var bytes32 [32]byte
	if len(data)!=2400{
		err=errors.New("input data for Bytes_to_768_Sk must be 2400 bytes long")
		return
	}
	sk=new(sk_768)//seed is left alone
	kyber_ops.Decode_12(data,&sk.sk)
	copy(sk.Pk_Bytes[:],data[1152:])
	kyber_ops.Decode_12(sk.Pk_Bytes[:],&sk.pk)
	copy(bytes32[:],data[2336:])
	test32:=sha3.Sum256(sk.Pk_Bytes[:])
	if test32!=bytes32{
		err=errors.New("public key mismatch")
		return
	}
	copy(sk.z[:],data[2368:])
	return
}

func Bytes_to_Pk_90s(data []byte)(pk *pk_768_90s,err error){
	if len(data)!=1184{
		err=errors.New("input data for Bytes_to_768_Pk must be 1184 bytes long")
		return
	}
	pk=new(pk_768_90s)
	copy(pk.Bytes[:],data)
	copy(pk.p[:],data[1152:])
	kyber_ops.Decode_12(data,&pk.pk)
	return
}

func Bytes_to_Sk_90s(data []byte)(sk *sk_768_90s,err error){
	var bytes32 [32]byte
	if len(data)!=2400{
		err=errors.New("input data for Bytes_to_768_Sk must be 2400 bytes long")
		return
	}
	sk=new(sk_768_90s)//seed is left alone
	kyber_ops.Decode_12(data,&sk.sk)
	copy(sk.Pk_Bytes[:],data[1152:])
	kyber_ops.Decode_12(sk.Pk_Bytes[:],&sk.pk)
	copy(bytes32[:],data[2336:])
	test32:=sha256.Sum256(sk.Pk_Bytes[:])
	if test32!=bytes32{
		err=errors.New("public key mismatch")
		return
	}
	copy(sk.z[:],data[2368:])
	return
}

func Keygen()*sk_768{
	keys:=new(sk_768)
	kyber_ops.Read_RNG(keys.Seed[:])
	seed_keygen_768(keys)
	return keys
}

func (sk *sk_768)To_Bytes()(data [cc_sk_768_len]byte){
	kyber_ops.Encode_12(&sk.sk,data[:])
	copy(data[cp_sk_768_len:],sk.Pk_Bytes[:])
	copy(data[cc_sk_768_len-64:],sk.h[:])
	copy(data[cc_sk_768_len-32:],sk.z[:])
	return
}

func (sk *sk_768_90s)To_Bytes()(data [cc_sk_768_len]byte){
	kyber_ops.Encode_12(&sk.sk,data[:])
	copy(data[cp_sk_768_len:],sk.Pk_Bytes[:])
	copy(data[cc_sk_768_len-64:],sk.h[:])
	copy(data[cc_sk_768_len-32:],sk.z[:])
	return
}

func Seed_to_Keys(seed [32]byte)(*sk_768,error){
	if seed==[32]byte{}{
		return nil,errors.New("keys can not be recovered, nil seed")
	}
	keys:=new(sk_768)
	keys.Seed=seed
	seed_keygen_768(keys)
	return keys,nil
}

func seed_keygen_768(keys *sk_768){
	var(
		i,j uint8
		A [k_768][k_768][256]int16
		e [k_768][256]int16
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
	for i=0;i<k_768;i++{
		p[33]=i
		for j=0;j<k_768;j++{
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
	for i=0;i<k_768;i++{
		kyber_ops.Mul_matrix(&keys.sk,&A[i],&keys.pk[i],&t)
		kyber_ops.Mont_poly(&keys.pk[i])
	}
	kyber_ops.Add_vec(&keys.pk,&e,&keys.pk)
	kyber_ops.Mod_vec(&keys.pk)
	kyber_ops.CSUBQ_vec(&keys.sk)
	kyber_ops.CSUBQ_vec(&keys.pk)
	kyber_ops.Encode_12(&keys.pk,keys.Pk_Bytes[:])
	copy(keys.Pk_Bytes[cp_sk_768_len:],p[:])
	kyber_ops.Read_RNG(keys.z[:])
	keys.h=sha3.Sum256(keys.Pk_Bytes[:])
}

func cpapke_enc_768(pk *[k_768][256]int16,m [32]byte,temp_r,temp_p []byte)(c [ciphertext_768_len]byte){
	var(
		i,j uint8
		A [k_768][k_768][256]int16
		s,e1,u [k_768][256]int16
		e2,v,t [256]int16
		bytes128 [128]byte
		r [33]byte
		p [34]byte
	)
	copy(r[:],temp_r)
	copy(p[:],temp_p)
	xof:=sha3.NewShake128()
	shake:=sha3.NewShake256()
	for i=0;i<k_768;i++{
		p[32]=i
		for j=0;j<k_768;j++{
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
	for i=0;i<k_768;i++{
		kyber_ops.Mul_matrix(&A[i],&s,&u[i],&t)
	}
	kyber_ops.Mul_matrix(pk,&s,&v,&t)
	for i=0;i<k_768;i++{
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
	kyber_ops.Com_10(&u,c[:])
	kyber_ops.Com_4(&v,c[ciphertext_768_len-128:])
	return
}

func cpapke_dec_768(sk *[k_768][256]int16,c []byte)(m [32]byte){
	var u [k_768][256]int16
	var v,mp [256]int16
	kyber_ops.Decom_10(c[:],&u)
	kyber_ops.NTT_vec(&u)
	kyber_ops.Mul_matrix(sk,&u,&mp,&v)
	kyber_ops.Inv(&mp)
	kyber_ops.Decom_4(c[ciphertext_768_len-128:],&v)
	kyber_ops.Sub_poly(&v,&mp,&mp)
	kyber_ops.Mod_poly(&mp)
	kyber_ops.Com_1(&mp,m[:])
	return
}

func (pk *pk_768)Enc(Shared_key_length int)(c [ciphertext_768_len]byte,K []byte){
	var m,temp [32]byte
	kyber_ops.Read_RNG(m[:])
	m=sha3.Sum256(m[:])
	G:=sha3.New512()
	G.Write(m[:])
	temp=sha3.Sum256(pk.Bytes[:])
	G.Write(temp[:])
	Kr:=G.Sum(nil)
	c=cpapke_enc_768(&pk.pk,m,Kr[32:],pk.p[:])
	KDF:=sha3.NewShake256()
	KDF.Write(Kr[:32])
	temp=sha3.Sum256(c[:])
	KDF.Write(temp[:])
	K=make([]byte,Shared_key_length)
	KDF.Read(K[:])
	return
}

func (sk *sk_768)Dec(c []byte,Shared_key_length int)(K []byte,err error){
	if len(c)!=ciphertext_768_len{
		err=errors.New("ciphertext must be 1088 bytes long")
		return
	}
	m:=cpapke_dec_768(&sk.sk,c)
	G:=sha3.New512()
	G.Write(m[:])
	G.Write(sk.h[:])
	Kr:=G.Sum(nil)
	c_:=cpapke_enc_768(&sk.pk,m,Kr[32:],sk.Pk_Bytes[pk_768_len-32:])
 	KDF:=sha3.NewShake256()
	H:=sha3.New256()
	H.Write(c)
	if c_==*(*[1088]byte)(c){
		KDF.Write(H.Sum(Kr[:32]))
	}else{
		KDF.Write(H.Sum(sk.z[:]))
	}
	K=make([]byte,Shared_key_length)
	KDF.Read(K)
	return
}

func Keygen_90s()*sk_768_90s{
	keys:=new(sk_768_90s)
	kyber_ops.Read_RNG(keys.Seed[:])
	seed_keygen_768_90s(keys)
	return keys
}

func Seed_to_Keys_90s(seed [32]byte)(*sk_768_90s,error){
	if seed==[32]byte{}{
		return nil,errors.New("keys can not be recovered, nil seed")
	}
	keys:=new(sk_768_90s)
	keys.Seed=seed
	seed_keygen_768_90s(keys)
	return keys,nil
}

func seed_keygen_768_90s(keys *sk_768_90s){
	var(
		i,j uint8
		A [k_768][k_768][256]int16
		e [k_768][256]int16
		t [256]int16
		bytes128 [128]byte
		iv [16]byte
	)
	temp:=sha512.Sum512(keys.Seed[:])
	xof,_:=aes.NewCipher(temp[:32])
	PRF,_:=aes.NewCipher(temp[32:])
	for i=0;i<k_768;i++{
		iv[1]=i
		for j=0;j<k_768;j++{
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
	for i=0;i<k_768;i++{
		kyber_ops.Mul_matrix(&keys.sk,&A[i],&keys.pk[i],&t)
		kyber_ops.Mont_poly(&keys.pk[i])
	}
	kyber_ops.Add_vec(&keys.pk,&e,&keys.pk)
	kyber_ops.Mod_vec(&keys.pk)
	kyber_ops.CSUBQ_vec(&keys.sk)
	kyber_ops.CSUBQ_vec(&keys.pk)
	kyber_ops.Encode_12(&keys.pk,keys.Pk_Bytes[:])
	copy(keys.Pk_Bytes[cp_sk_768_len:],temp[:])
	kyber_ops.Read_RNG(keys.z[:])
	keys.h=sha256.Sum256(keys.Pk_Bytes[:])
}

func cpapke_enc_768_90s(pk *[k_768][256]int16,m [32]byte,temp_r,temp_p []byte)(c [ciphertext_768_len]byte){
	var(
		i,j uint8
		A [k_768][k_768][256]int16
		s,e1,u [k_768][256]int16
		e2,v,t [256]int16
		bytes128 [128]byte
		iv [16]byte
	) 
	xof,_:=aes.NewCipher(temp_p)
	PRF,_:=aes.NewCipher(temp_r)
	for i=0;i<k_768;i++{
		iv[0]=i
		for j=0;j<k_768;j++{
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
	for i=0;i<k_768;i++{
		kyber_ops.Mul_matrix(&A[i],&s,&u[i],&t)
	}
	kyber_ops.Mul_matrix(pk,&s,&v,&t)
	for i=0;i<k_768;i++{
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
	kyber_ops.Com_10(&u,c[:])
	kyber_ops.Com_4(&v,c[ciphertext_768_len-128:])
	return
}

func (pk *pk_768_90s)Enc()(c [ciphertext_768_len]byte,K [32]byte){
	var m,temp [32]byte
	kyber_ops.Read_RNG(m[:])
	m=sha256.Sum256(m[:])
	G:=sha512.New()
	G.Write(m[:])
	temp=sha256.Sum256(pk.Bytes[:])
	G.Write(temp[:])
	Kr:=G.Sum(nil)
	c=cpapke_enc_768_90s(&pk.pk,m,Kr[32:],pk.p[:])
	H:=sha256.New()
	H.Write(c[:])
	K=sha256.Sum256(H.Sum(Kr[:32]))
	return
}

func (sk *sk_768_90s)Dec(c []byte)(K [32]byte,err error){
	if len(c)!=ciphertext_768_len{
		err=errors.New("ciphertext must be 1088 bytes long")
		return
	}
	m:=cpapke_dec_768(&sk.sk,c)
	G:=sha512.New()
	G.Write(m[:])
	G.Write(sk.h[:])
	Kr:=G.Sum(nil)
	c_:=cpapke_enc_768_90s(&sk.pk,m,Kr[32:],sk.Pk_Bytes[pk_768_len-32:])
	H:=sha256.New()
	H.Write(c[:])
	if c_==*(*[1088]byte)(c){
		K=sha256.Sum256(H.Sum(Kr[:32]))
	}else{
		K=sha256.Sum256(H.Sum(sk.z[:]))
	}
	return
}

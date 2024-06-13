/*Copyright (c) 2023 Tracy-Tzu under the MIT license
The kyber algorithm has a license that can be found in the file titled "nist-pqc-license-summary-and-excerpts.pdf"

Go port of the kyber post quantum encryption algorithm laid out by the NIST round 3 package that can be found by following the link below:
https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022

This file contains common code used for kyber_512,kyber_768,and kyber_1024
*/
package kyber_ops

import(
	"encoding/binary"
	"crypto/cipher"
	"golang.org/x/crypto/sha3"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
)

const K_512,K_768,K_1024=2,3,4
const q,q_inv,half_q,half_q_plus=3329,62209,q>>1,half_q+1

var zetas=[128]int16{2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628}
var zetas_inv=[128]int16{1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,3127, 3042, 1907, 1836, 1517, 359, 758, 1441}

type vec interface{
	*[K_512][256]int16|*[K_768][256]int16|*[K_1024][256]int16
}

type rng_info struct{
	key [32]byte
	iv [16]byte
}

func Init_Seed(str string)(err error){
	temp_data,err:=hex.DecodeString(str[:96])
	if err!=nil{
		return
	}
	init_rng((*[48]byte)(temp_data))
	return
}

var rng rng_info
var test_rand bool=false

func Set_test_rand(){
	test_rand=true
}

func init_rng(seed *[48]byte){
	rng.iv=[16]byte{}
	rng.key=[32]byte{}
	update_rng(seed)
}

func Read_RNG(rand_data []byte){
	if !test_rand{
		rand.Read(rand_data)
		return
	}
	cipher,_:=aes.NewCipher(rng.key[:])
	length:=len(rand_data)
	for cur:=0;cur<length;cur+=16{
		aes_count(&rng.iv)
		cipher.Encrypt(rand_data[cur:],rng.iv[:])
	}
	update_rng(nil)
}

func update_rng(addion *[48]byte){
	cipher,_:=aes.NewCipher(rng.key[:])
	for i:=0;i<32;i+=16{
		aes_count(&rng.iv)
		cipher.Encrypt(rng.key[i:],rng.iv[:])
	}
	aes_count(&rng.iv)
	cipher.Encrypt(rng.iv[:],rng.iv[:])
	if addion!=nil{
		for i:=0;i<32;i++{
			rng.key[i]^=addion[i]
		}
		I:=32
		for i:=0;i<16;i++{
			rng.iv[i]^=addion[I]
			I++
		}
	}
}

func CBD2(B *[128]byte,f *[256]int16){
	const b101=0x55555555
	var(
		a,b,t,d uint32
		i,i2,j,j4 uint
	)
	for i=0;i<128;i+=4{
		i2=i<<1
		t=binary.LittleEndian.Uint32(B[i:])
		d=t&b101
		d+=(t>>1)&b101
		for j=0;j<8;j++{
			j4=j<<2
			a=(d>>j4)&3
			b=(d>>(j4+2))&3
			f[i2+j]=int16(a-b)
		}
	}
}

func CBD3(B *[192]byte,f *[256]int16){
	const b1001=0x249249
	var(
		bytes4 [4]byte
		a,b,t,d uint32
		i,i3,i4,j,j6 uint
	)
	for i=0;i<64;i++{
		i4=i<<2
		copy(bytes4[:3],B[i3:])
		t=binary.LittleEndian.Uint32(bytes4[:])
		d=t&b1001
		d+=(t>>1)&b1001
		d+=(t>>2)&b1001
		for j=0;j<4;j++{
			j6=j*6
			a=(d>>j6)&7
			b=(d>>(j6+3))&7
			f[i4+j]=int16(a-b)
		}
		i3+=3
	}
}

func CBD2_cycle_shake[v vec](f v,bytes128 *[128]byte,r *[33]byte,shake sha3.ShakeHash){
	k:=len(f)
	for i:=0;i<k;i++{
		shake.Write(r[:])
		shake.Read(bytes128[:])
		CBD2(bytes128,&f[i])
		shake.Reset()
		r[32]++
	}
}

func CBD3_cycle_shake[v vec](f v,bytes192 *[192]byte,r *[33]byte,shake sha3.ShakeHash){
	k:=len(f)
	for i:=0;i<k;i++{
		shake.Write(r[:])
		shake.Read(bytes192[:])
		CBD3(bytes192,&f[i])
		shake.Reset()
		r[32]++
	}
}

func CBD2_cycle_aes[v vec](f v,bytes128 *[128]byte,iv *[16]byte,aes cipher.Block){
	k:=len(f)
	for i:=0;i<k;i++{
		AES_encrypt_128(aes,bytes128,iv)
		CBD2(bytes128,&f[i])
		iv[0]++
		iv[15]=0
	}
}

func CBD3_cycle_aes[v vec](f v,bytes192 *[192]byte,iv *[16]byte,aes cipher.Block){
	k:=len(f)
	for i:=0;i<k;i++{
		aes_encrypt_192(aes,bytes192,iv)
		CBD3(bytes192,&f[i])
		iv[0]++
		iv[15]=0
	}
}

func csubq(a int16)int16{
	a-=q
	return a+((a>>15)&q)
}

func mont_mod(a int32)int16{
	u:=(a*q_inv)&0xFFFF
	t:=u*q
	t=a-t
	t>>=16
	return int16(t)
}

func bar_mod(a int16)int16{
	const v=(q/2+0x4000000)/q
	t:=int16(v*int32(a)>>26)*q
	return a-t
}

func fqmul(a,b int16)int16{
	return mont_mod(int32(a)*int32(b))
}

func Mod_poly(f *[256]int16){
	for i,fi:=range f{
		f[i]=bar_mod(fi)
	}
}

func CSUBQ_poly(f *[256]int16){
	for i,fi:=range f{
		f[i]=csubq(fi)
	}
}

func Add_poly(f,g,fg *[256]int16){
	for i,fi:=range f{
		fg[i]=fi+g[i]
	}
}

func Sub_poly(f,g,fg *[256]int16){
	for i,fi:=range f{
		fg[i]=fi-g[i]
	}
}

func mul_base(f,g,fg []int16,zeta int16){
	fg[1]=fqmul(f[0],g[1])+fqmul(f[1],g[0])
	fg[0]=fqmul(fqmul(f[1],g[1]),zeta)+fqmul(f[0],g[0])
}

func mul_poly(f,g,fg *[256]int16){
	var i,i4 uint32
	var zeta int16
	for i=0;i<64;i++{
		i4=i<<2
		zeta=zetas[i+64]
		mul_base(f[i4:],g[i4:],fg[i4:],zeta)
		i4+=2
		mul_base(f[i4:],g[i4:],fg[i4:],-zeta)
	}
}

func Mont_poly(f *[256]int16){
	const fc=1353
	for i,r:=range f{
		f[i]=mont_mod(int32(r)*fc)
	}
}

func Mul_matrix[v vec](f,g v,fg,temp *[256]int16){
	mul_poly(&f[0],&g[0],fg)
	k:=len(f)
	for i:=1;i<k;i++{
		mul_poly(&f[i],&g[i],temp)
		Add_poly(fg,temp,fg)
	}
	Mod_poly(fg)
}

func ntt(f *[256]int16){
	var l,start,j,k uint
	var t,zeta int16
	k=1
	for l=128;l>1;l>>=1{
		for start=0;start<256;start=j+l{
			zeta=zetas[k]
			k++
			for j=start;j<start+l;j++{
				t=fqmul(zeta,f[j+l])
				f[j+l]=f[j]-t
				f[j]+=t
			}
		}
	}
	Mod_poly(f)
}

func Inv(f *[256]int16){
	var l,start,j,k uint
	var t,zeta int16
	for l=2;l<=128;l<<=1{
		for start=0;start<256;start=j+l{
			zeta=zetas_inv[k]
			k++
			for j=start;j<start+l;j++{
				t=f[j]
				f[j]=bar_mod(t+f[j+l])
				f[j+l]=fqmul(zeta,t-f[j+l])
			}
		}
	}
	for j=0;j<256;j++{
		f[j]=fqmul(f[j],zetas_inv[127])
	}
}

func NTT_vec[v vec](f v){
	k:=len(f)
	for i:=0;i<k;i++{
		ntt(&f[i])
	}
}

func Add_vec[v vec](f,g,fg v){
	k:=len(f)
	for i:=0;i<k;i++{
		Add_poly(&f[i],&g[i],&fg[i])
	}
}

func Mod_vec[v vec](f v){
	k:=len(f)
	for i:=0;i<k;i++{
		Mod_poly(&f[i])
	}
}

func CSUBQ_vec[v vec](f v){
	k:=len(f)
	for i:=0;i<k;i++{
		CSUBQ_poly(&f[i])
	}
}

func aes_count(iv *[16]byte){
	for i:=15;i>=0;i--{
		iv[i]++
		if iv[i]>0{
			break
		}
	}
}

func AES_encrypt_128(stream cipher.Block,bytes128 *[128]byte,iv *[16]byte){
	for i:=0;i<128;i+=16{
		stream.Encrypt(bytes128[i:],iv[:])
		iv[15]++
	}
}

func aes_encrypt_192(stream cipher.Block,bytes192 *[192]byte,iv *[16]byte){
	for i:=0;i<192;i+=16{
		stream.Encrypt(bytes192[i:],iv[:])
		iv[15]++
	}
}

func Parse_shake(f *[256]int16,stream sha3.ShakeHash){
	var(
		bytes3 [3]byte
		j uint
		d1,d2,b1 int16
	)
	for j<256{
		stream.Read(bytes3[:])
		b1=int16(bytes3[1])
		d1=int16(bytes3[0])+(b1&15)<<8
		d2=b1>>4+int16(bytes3[2])<<4
		if d1<q{
			f[j]=d1
			j++
		}
		if d2<q&&j<256{
			f[j]=d2
			j++
		}
	}
}

func Parse_aes(f *[256]int16,stream cipher.Block,iv *[16]byte){
	var (
		bytes16 [16]byte
		bytes3 [3]byte
		i,j uint
		d1,d2,b1 int16
	)
	stream.Encrypt(bytes16[:],iv[:])
	for j<256{
		copy(bytes3[:],bytes16[i:])
		i+=3
		if i>15{
			aes_count(iv)
			stream.Encrypt(bytes16[:],iv[:])
			i-=16
			if i!=0{
				copy(bytes3[3-i:],bytes16[:i])
			}
		}
		b1=int16(bytes3[1])
		d1=int16(bytes3[0])+(b1&15)<<8
		d2=b1>>4+int16(bytes3[2])<<4
		if d1<q{
			f[j]=d1
			j++
		}
		if d2<q&&j<256{
			f[j]=d2
			j++
		}
	}
}

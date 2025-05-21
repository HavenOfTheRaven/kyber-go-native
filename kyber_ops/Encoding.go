/*Copyright (c) 2025 Haven F.C. Johnson under the MIT license
The kyber algorithm has a license that can be found in the file titled "nist-pqc-license-summary-and-excerpts.pdf"

Go port of the kyber post quantum encryption algorithm laid out by the NIST round 3 package that can be found by following the link below:
https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022

This file contains code to encode and decode polynomials and vectors used for kyber_512,kyber_768,and kyber_1024
*/
package kyber_ops

type two_vec interface{
	*[K_512][256]int16|*[K_768][256]int16
}

func Encode_12[v vec](f v,B []byte){
	var i,i3 uint
	var r0,r1 int16
	k:=len(f)
	for I:=0;I<k;I++{
		for i=0;i<256;i+=2{
			r0,r1=f[I][i],f[I][i+1]
			B[i3]=byte(r0)
			B[i3+1]=byte((r0>>8)|(r1<<4))
			B[i3+2]=byte(r1>>4)
			i3+=3
		}
	}
}

func Decode_12[v vec](B []byte,f v){
	var i,i3 uint
	var b1 int16
	k:=len(f)
	for I:=0;I<k;I++{
		for i=0;i<256;i+=2{
			b1=int16(B[i3+1])
			f[I][i]=((b1&15)<<8)|int16(B[i3])
			f[I][i+1]=(b1>>4)|(int16(B[i3+2])<<4)
			i3+=3
		}
	}
}

func Com_1(f *[256]int16,com []byte){
	var i,j,pt uint
	for i=0;i<256;i+=8{
		for j=0;j<8;j++{
			com[pt]|=byte((((f[i+j]<<1)+half_q)/q)&1)<<j
		}
		pt++
	}
}

func Com_4(f *[256]int16,com []byte){
	var i,j,ci uint
	var t [8]uint16
	for i=0;i<256;i+=8{
		for j=0;j<8;j++{
			t[j]=(((uint16(f[i+j])<<4)+half_q)/q)&15
		}
		com[ci]=uint8(t[0]|(t[1]<<4))
		com[ci+1]=uint8(t[2]|(t[3]<<4))
		com[ci+2]=uint8(t[4]|(t[5]<<4))
		com[ci+3]=uint8(t[6]|(t[7]<<4))
		ci+=4
	}
}

func Com_5(f *[256]int16,com []byte){
	var i,j,ci uint
	var t [8]uint32
	for i=0;i<256;i+=8{
		for j=0;j<8;j++{
			t[j]=(((uint32(f[i+j])<<5)+half_q)/q)&31
		}
		com[ci]=uint8(t[0]|(t[1]<<5))
		com[ci+1]=uint8((t[1]>>3)|(t[2]<<2)|(t[3]<<7))
		com[ci+2]=uint8((t[3]>>1)|(t[4]<<4))
		com[ci+3]=uint8((t[4]>>4)|(t[5]<<1)|(t[6]<<6))
		com[ci+4]=uint8((t[6]>>2)|(t[7]<<3))
		ci+=5
	}
}

func Com_10[v two_vec](f v,com []byte){
	var i,j,ci uint
	var t [4]uint32
	k:=len(f)
	for I:=0;I<k;I++{
		for i=0;i<256;i+=4{
			for j=0;j<4;j++{
				t[j]=(((uint32(f[I][i+j])<<10)+half_q)/q)&1023
			}
			com[ci]=uint8(t[0])
			com[ci+1]=uint8((t[0]>>8)|(t[1]<<2))
			com[ci+2]=uint8((t[1]>>6)|(t[2]<<4))
			com[ci+3]=uint8((t[2]>>4)|(t[3]<<6))
			com[ci+4]=uint8(t[3]>>2)
			ci+=5
		}
	}
}

func Com_11(f *[K_1024][256]int16,com []byte){
	var i,j,ci uint
	var t [8]uint32
	for _,poly:=range f{
		for i=0;i<256;i+=8{
			for j=0;j<8;j++{
				t[j]=(((uint32(poly[i+j])<<11)+half_q)/q)&2047
			}
			com[ci]=uint8(t[0])
			com[ci+1]=uint8((t[0]>>8)|(t[1]<<3))
			com[ci+2]=uint8((t[1]>>5)|(t[2]<<6))
			com[ci+3]=uint8(t[2]>>2)
			com[ci+4]=uint8((t[2]>>10)|(t[3]<<1))
			com[ci+5]=uint8((t[3]>>7)|(t[4]<<4))
			com[ci+6]=uint8((t[4]>>4)|(t[5]<<7))
			com[ci+7]=uint8(t[5]>>1)
			com[ci+8]=uint8((t[5]>>9)|(t[6]<<2))
			com[ci+9]=uint8((t[6]>>6)|(t[7]<<5))
			com[ci+10]=uint8(t[7]>>3)
			ci+=11
		}
	}
}

func Decom_1(com []byte,f *[256]int16){
	var i,j,pt uint
	var t int16
	for i=0;i<256;i+=8{
		t=int16(com[pt])
		for j=0;j<8;j++{
			f[i+j]=(-((t>>j)&1))&half_q_plus
		}
		pt++
	}
}


func Decom_4(com []byte,f *[256]int16){
	var i,j uint
	var t int16
	for i=0;i<256;i+=2{
		t=int16(com[j])
		f[i]=int16(((uint16(t&15)*q)+8)>>4)
		f[i+1]=int16(((uint16(t>>4)*q)+8)>>4)
		j++
	}
}

func Decom_5(com []byte,f *[256]int16){
	var i,j,ci uint
	var t [5]int16
	for i=0;i<256;i+=8{
		for j=0;j<5;j++{
			t[j]=int16(com[ci])
			ci++
		}
		f[i]=t[0]
		f[i+1]=(t[0]>>5)|(t[1]<<3)
		f[i+2]=t[1]>>2
		f[i+3]=(t[1]>>7)|(t[2]<<1)
		f[i+4]=(t[2]>>4)|(t[3]<<4)
		f[i+5]=t[3]>>1
		f[i+6]=(t[3]>>6)|(t[4]<<2)
		f[i+7]=t[4]>>3
	}
	for j=0;j<256;j++{
		f[j]=int16((uint32(f[j]&31)*q+16)>>5)
	}
}

func Decom_10[v two_vec](com []byte,f v){
	var i,j,ci uint
	var t [5]int16
	k:=len(f)
	for I:=0;I<k;I++{
		for i=0;i<256;i+=4{
			for j=0;j<5;j++{
				t[j]=int16(com[ci])
				ci++
			}
			f[I][i]=t[0]|(t[1]<<8)
			f[I][i+1]=(t[1]>>2)|(t[2]<<6)
			f[I][i+2]=(t[2]>>4)|(t[3]<<4)
			f[I][i+3]=(t[3]>>6)|(t[4]<<2)
		}
		for i=0;i<256;i++{
			f[I][i]=int16((uint32(f[I][i]&1023)*q+512)>>10)
		}
	}
}

func Decom_11(com []byte,f *[K_1024][256]int16){
	var i,j,ci uint
	var t [11]int16
	for I,poly:=range f{
		for i=0;i<256;i+=8{
			for j=0;j<11;j++{
				t[j]=int16(com[ci])
				ci++
			}
			poly[i]=t[0]|(t[1]<<8)
			poly[i+1]=(t[1]>>3)|(t[2]<<5)
			poly[i+2]=(t[2]>>6)|(t[3]<<2)|(t[4]<<10)
			poly[i+3]=(t[4]>>1)|(t[5]<<7)
			poly[i+4]=(t[5]>>4)|(t[6]<<4)
			poly[i+5]=(t[6]>>7)|(t[7]<<1)|(t[8]<<9)
			poly[i+6]=(t[8]>>2)|(t[9]<<6)
			poly[i+7]=(t[9]>>5)|(t[10]<<3)
		}
		for i=0;i<256;i++{
			poly[i]=int16((uint32(poly[i]&2047)*q+1024)>>11)
		}
		f[I]=poly
	}
}

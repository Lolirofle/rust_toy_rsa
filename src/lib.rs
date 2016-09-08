#![feature(non_ascii_idents)]

/*
 * Everything here is implemented according to information received from
 *   Wikipedia @ 2016-09-08 12:40 UTC+01:00
 * using the following articles:
 *   https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29
 *   https://en.wikipedia.org/wiki/Generating_primes
 *   https://en.wikipedia.org/wiki/Binary_GCD_algorithm
 *   https://en.wikipedia.org/wiki/Euclidean_algorithm
 *   https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
 *   https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
 *   https://en.wikipedia.org/wiki/Modular_exponentiation
 */

extern crate core;
extern crate itertools;
extern crate num;
extern crate rand;

use core::ops::Shr;
use itertools::RepeatCall;
use num::{Integer,One,Zero};
use rand::distributions::range::SampleRange;

pub type KeyPair<N> = (PublicKey<N>,PrivateKey<N>);

#[derive(Copy,Clone,Debug,Eq,PartialEq)]
pub struct PublicKey<N>(N,N);
#[derive(Copy,Clone,Debug,Eq,PartialEq)]
pub struct PrivateKey<N>(N);

pub fn gen_key_pair<N,Rng>(p: N,q: N,rng: &mut Rng) -> KeyPair<N> where
	N: Integer + SampleRange + Copy,
	Rng: rand::Rng
{
	let n = p*q;

	//A totient of n
	//φ(n) = φ(p)*φ(q)
	let φ = (p-One::one())*(q-One::one());

	//Choose a number that is not a divisor of φ and lesser than φ
	//(satisfying (gcd(e,φ)=1 , 1<e<φ))
	let e = RepeatCall::new(|| rng.gen_range(One::one(),φ)).find(|x| φ.gcd(x)==One::one()).unwrap();

	//Find the modular multiplicative inverse of e in modulo φ
	//using the Euclidean algorithm
	//(satisfying ((d*e) mod φ = 1) , d>=0)
	let d = {
		let inv = util::mod_mult_inv(φ,e);
		if inv < Zero::zero(){inv+φ}else{inv}
	};

	(PublicKey(n,e),PrivateKey(d))
}

pub fn encrypt<N>(data: N,key: PublicKey<N>) -> N where
	N: Integer + Copy + Shr<N,Output=N>
{
	util::mod_pow(data,key.1,key.0)
}

pub fn decrypt<N>(data: N,(public_key,private_key): KeyPair<N>) -> N where
	N: Integer + Copy + Shr<N,Output=N>
{
	util::mod_pow(data,private_key.0,public_key.0)
}

pub mod util{
	use core::ops::Shr;
	use num::{Integer,One,Zero};

	/**
	 * A modular multiplicative inverse of r1 in modulo r2
	 * Implemented using the extended Euclidean algorithm
	 */
	pub fn mod_mult_inv<N>(mut r1: N,mut r2: N) -> N where
		N: Integer + Copy
	{
		let (mut t1,mut t2) = (Zero::zero(),One::one());

		while r2!=Zero::zero(){
			let (div,rem) = r1.div_rem(&r2);
			r1 = r2;
			r2 = rem;

			let old_t1 = t1;
			t1 = t2;
			t2 = old_t1-div*t2;
		}

		t1
	}

	/**
	 * The binary operation (base exponentiated to the exponent) and its result modulo modulo
	 * Implemented using the Right-to-left binary method described on Wikipedia
	 * which states that this method was based of pseudocode in Applied Cryptography by Bruce Schneier
	 */
	pub fn mod_pow<N>(mut base: N,mut exponent: N,modulo: N) -> N where
		N: Integer + Copy + Shr<N,Output=N>
	{
		let two = N::one()+N::one();

		let mut out = One::one();
		base = base%modulo;

		while exponent>Zero::zero(){
			if exponent%two == One::one(){
				out = (out*base) % modulo;
			}
			exponent = exponent >> One::one();
			base = (base*base) % modulo;
		}

		out
	}
}

#[cfg(test)]
mod tests{
	#[test]
	fn mod_pow(){
		assert_eq!(super::util::mod_pow(3120,17,2753),1046);
		assert_eq!(super::util::mod_pow(240,46,47),1);
	}
	#[test]
	fn mod_mult_inv(){
		assert_eq!(super::util::mod_mult_inv(3120,17),-367);
		assert_eq!(super::util::mod_mult_inv(240,46),47);
	}
	#[test]
	fn gen_key_pair(){
		use std::io;
		use num::Integer;
		use rand::StdRng;

		let mut rng = StdRng::new().unwrap();
		let (p,q): (i64,i64) = (3120,17);
		let φ = (p-1)*(q-1);
		let (super::PublicKey(n,e),super::PrivateKey(d)) = super::gen_key_pair(p,q,&mut rng);

		assert!(1<e);
		assert!(e<φ);
		assert_eq!(φ.gcd(&e),1);
		assert!(d>=0);
		assert_eq!((d*e)%φ,1);
	}
	#[test]
	fn encrypt_decrypt(){
		use std::io;
		use num::Integer;
		use rand::StdRng;

		let mut rng = StdRng::new().unwrap();
		let (p,q): (i64,i64) = (61,53);
		let (public,private) = super::gen_key_pair(p,q,&mut rng);

		assert_eq!(super::decrypt(super::encrypt(50,public),(public,private)),50);
	}
}

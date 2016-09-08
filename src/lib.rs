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
 */

extern crate core;
extern crate itertools;
extern crate num;
extern crate rand;

use itertools::RepeatCall;
use num::{Integer,One};
use num::pow::pow;
use rand::distributions::range::SampleRange;

pub type KeyPair<N> = (PublicKey<N>,PrivateKey<N>);

pub struct PublicKey<N>(N,N);
pub struct PrivateKey<N>(N);

pub fn gen_key_pair<N,Rng>(p: N,q: N,rng: &mut Rng) -> KeyPair<N> where
	N: Integer + SampleRange + Copy,
	Rng: rand::Rng
{
	let n = p*q;

	//A totient of the product
	let φ = (p-One::one())*(q-One::one());

	//Choose a number that is not a divisor of φ
	//(satisfying (gcd(x,φ) = 1))
	let e = RepeatCall::new(|| rng.gen_range(One::one(),φ)).find(|x| φ.gcd(x)==One::one()).unwrap();

	//Find the modular multiplicative inverse of e in modulo φ
	//using the Euclidean algorithm
	//(satisfying ((d*e) mod φ = 1))
	let d = util::mod_mult_inv(φ,e);

	(PublicKey(n,e),PrivateKey(d))
}

pub fn encrypt<N>(data: N,key: PublicKey<N>) -> N where
	N: Integer + Copy + Into<usize>
{
	pow(data,key.1.into()) % key.0
}

pub fn decrypt<N>(data: N,(public_key,private_key): KeyPair<N>) -> N where
	N: Integer + Copy + Into<usize>
{
	pow(data,private_key.0.into()) % public_key.0
}

pub mod util{
	use num::{Integer,One,Zero};

	/**
	 * The modular multiplicative inverse of r1 in modulo r2
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
}



#[cfg(test)]
mod tests{
	#[test]
	fn mod_mult_inv(){
		assert_eq!(super::util::mod_mult_inv(3120,17),-367);
		assert_eq!(super::util::mod_mult_inv(240,46),47);
	}
}

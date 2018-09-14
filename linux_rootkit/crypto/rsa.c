/*
 * 
 * 
 * Implementation is derived from https://mattmccutchen.net/bigint/.
 * 
 * Author: Daniel Liscinsky
 */



#include "rsa.h"



 /*
 * About the multiplication and division algorithms:
 *
 * I searched unsucessfully for fast C++ built-in operations like the `b_0'
 * and `c_0' Knuth describes in Section 4.3.1 of ``The Art of Computer
 * Programming'' (replace `place' by `Blk'):
 *
 *    ``b_0[:] multiplication of a one-place integer by another one-place
 *      integer, giving a two-place answer;
 *
 *    ``c_0[:] division of a two-place integer by a one-place integer,
 *      provided that the quotient is a one-place integer, and yielding
 *      also a one-place remainder.''
 *
 * I also missed his note that ``[b]y adjusting the word size, if
 * necessary, nearly all computers will have these three operations
 * available'', so I gave up on trying to use algorithms similar to his.
 * A future version of the library might include such algorithms; I
 * would welcome contributions from others for this.
 *
 * I eventually decided to use bit-shifting algorithms.  To multiply `a'
 * and `b', we zero out the result.  Then, for each `1' bit in `a', we
 * shift `b' left the appropriate amount and add it to the result.
 * Similarly, to divide `a' by `b', we shift `b' left varying amounts,
 * repeatedly trying to subtract it from `a'.  When we succeed, we note
 * the fact by setting a bit in the quotient.  While these algorithms
 * have the same O(n^2) time complexity as Knuth's, the ``constant factor''
 * is likely to be larger.
 *
 * Because I used these algorithms, which require single-block addition
 * and subtraction rather than single-block multiplication and division,
 * the innermost loops of all four routines are very similar.  Study one
 * of them and all will become clear.
 */

 /*
 * This is a little inline function used by both the multiplication
 * routine and the division routine.
 *
 * `getShiftedBlock' returns the `x'th block of `num << y'.
 * `y' may be anything from 0 to N - 1, and `x' may be anything from
 * 0 to `num.len'.
 *
 * Two things contribute to this block:
 *
 * (1) The `N - y' low bits of `num.blk[x]', shifted `y' bits left.
 *
 * (2) The `y' high bits of `num.blk[x-1]', shifted `N - y' bits right.
 *
 * But we must be careful if `x == 0' or `x == num.len', in
 * which case we should use 0 instead of (2) or (1), respectively.
 *
 * If `y == 0', then (2) contributes 0, as it should.  However,
 * in some computer environments, for a reason I cannot understand,
 * `a >> b' means `a >> (b % N)'.  This means `num.blk[x-1] >> (N - y)'
 * will return `num.blk[x-1]' instead of the desired 0 when `y == 0';
 * the test `y == 0' handles this case specially.
 */
inline BigUnsigned::Blk getShiftedBlock(const BigUnsigned &num,
	BigUnsigned::Index x, unsigned int y) {
	BigUnsigned::Blk part1 = (x == 0 || y == 0) ? 0 : (num.blk[x - 1] >> (BigUnsigned::N - y));
	BigUnsigned::Blk part2 = (x == num.len) ? 0 : (num.blk[x] << y);
	return part1 | part2;
}

void multiply(const BigUnsigned &a, const BigUnsigned &b) {
	DTRT_ALIASED(this == &a || this == &b, multiply(a, b));
	// If either a or b is zero, set to zero.
	if (a.len == 0 || b.len == 0) {
		len = 0;
		return;
	}
	/*
	* Overall method:
	*
	* Set this = 0.
	* For each 1-bit of `a' (say the `i2'th bit of block `i'):
	*    Add `b << (i blocks and i2 bits)' to *this.
	*/
	// Variables for the calculation
	Index i, j, k;
	unsigned int i2;
	Blk temp;
	bool carryIn, carryOut;
	// Set preliminary length and make room
	len = a.len + b.len;
	allocate(len);
	// Zero out this object
	for (i = 0; i < len; i++)
		blk[i] = 0;
	// For each block of the first number...
	for (i = 0; i < a.len; i++) {
		// For each 1-bit of that block...
		for (i2 = 0; i2 < N; i2++) {
			if ((a.blk[i] & (Blk(1) << i2)) == 0)
				continue;
			/*
			* Add b to this, shifted left i blocks and i2 bits.
			* j is the index in b, and k = i + j is the index in this.
			*
			* `getShiftedBlock', a short inline function defined above,
			* is now used for the bit handling.  It replaces the more
			* complex `bHigh' code, in which each run of the loop dealt
			* immediately with the low bits and saved the high bits to
			* be picked up next time.  The last run of the loop used to
			* leave leftover high bits, which were handled separately.
			* Instead, this loop runs an additional time with j == b.len.
			* These changes were made on 2005.01.11.
			*/
			for (j = 0, k = i, carryIn = false; j <= b.len; j++, k++) {
				/*
				* The body of this loop is very similar to the body of the first loop
				* in `add', except that this loop does a `+=' instead of a `+'.
				*/
				temp = blk[k] + getShiftedBlock(b, j, i2);
				carryOut = (temp < blk[k]);
				if (carryIn) {
					temp++;
					carryOut |= (temp == 0);
				}
				blk[k] = temp;
				carryIn = carryOut;
			}
			// No more extra iteration to deal with `bHigh'.
			// Roll-over a carry as necessary.
			for (; carryIn; k++) {
				blk[k]++;
				carryIn = (blk[k] == 0);
			}
		}
	}
	// Zap possible leading zero
	if (blk[len - 1] == 0)
		len--;
}

/*
* DIVISION WITH REMAINDER
* This monstrous function mods *this by the given divisor b while storing the
* quotient in the given object q; at the end, *this contains the remainder.
* The seemingly bizarre pattern of inputs and outputs was chosen so that the
* function copies as little as possible (since it is implemented by repeated
* subtraction of multiples of b from *this).
* 
* "modWithQuotient" might be a better name for this function, but I would
* rather not change the name now.
*/
void divideWithRemainder(const BigUnsigned &b, BigUnsigned &q) {
	/* Defending against aliased calls is more complex than usual because we
	* are writing to both *this and q.
	* 
	* It would be silly to try to write quotient and remainder to the
	* same variable.  Rule that out right away. */
	//if (this == &q)
	//	throw "BigUnsigned::divideWithRemainder: Cannot write quotient and remainder into the same variable";
	/* Now *this and q are separate, so the only concern is that b might be
	* aliased to one of them.  If so, use a temporary copy of b. */
	if (this == &b || &q == &b) {
		BigUnsigned tmpB(b);
		divideWithRemainder(tmpB, q);
		return;
	}

	/*
	* Knuth's definition of mod (which this function uses) is somewhat
	* different from the C++ definition of % in case of division by 0.
	*
	* We let a / 0 == 0 (it doesn't matter much) and a % 0 == a, no
	* exceptions thrown.  This allows us to preserve both Knuth's demand
	* that a mod 0 == a and the useful property that
	* (a / b) * b + (a % b) == a.
	*/
	if (b.len == 0) {
		q.len = 0;
		return;
	}

	/*
	* If *this.len < b.len, then *this < b, and we can be sure that b doesn't go into
	* *this at all.  The quotient is 0 and *this is already the remainder (so leave it alone).
	*/
	if (len < b.len) {
		q.len = 0;
		return;
	}

	// At this point we know (*this).len >= b.len > 0.  (Whew!)

	/*
	* Overall method:
	*
	* For each appropriate i and i2, decreasing:
	*    Subtract (b << (i blocks and i2 bits)) from *this, storing the
	*      result in subtractBuf.
	*    If the subtraction succeeds with a nonnegative result:
	*        Turn on bit i2 of block i of the quotient q.
	*        Copy subtractBuf back into *this.
	*    Otherwise bit i2 of block i remains off, and *this is unchanged.
	* 
	* Eventually q will contain the entire quotient, and *this will
	* be left with the remainder.
	*
	* subtractBuf[x] corresponds to blk[x], not blk[x+i], since 2005.01.11.
	* But on a single iteration, we don't touch the i lowest blocks of blk
	* (and don't use those of subtractBuf) because these blocks are
	* unaffected by the subtraction: we are subtracting
	* (b << (i blocks and i2 bits)), which ends in at least `i' zero
	* blocks. */
	// Variables for the calculation
	Index i, j, k;
	unsigned int i2;
	Blk temp;
	bool borrowIn, borrowOut;

	/*
	* Make sure we have an extra zero block just past the value.
	*
	* When we attempt a subtraction, we might shift `b' so
	* its first block begins a few bits left of the dividend,
	* and then we'll try to compare these extra bits with
	* a nonexistent block to the left of the dividend.  The
	* extra zero block ensures sensible behavior; we need
	* an extra block in `subtractBuf' for exactly the same reason.
	*/
	Index origLen = len; // Save real length.
						 /* To avoid an out-of-bounds access in case of reallocation, allocate
						 * first and then increment the logical length. */
	allocateAndCopy(len + 1);
	len++;
	blk[origLen] = 0; // Zero the added block.

					  // subtractBuf holds part of the result of a subtraction; see above.
	Blk *subtractBuf = new Blk[len];

	// Set preliminary length for quotient and make room
	q.len = origLen - b.len + 1;
	q.allocate(q.len);
	// Zero out the quotient
	for (i = 0; i < q.len; i++)
		q.blk[i] = 0;

	// For each possible left-shift of b in blocks...
	i = q.len;
	while (i > 0) {
		i--;
		// For each possible left-shift of b in bits...
		// (Remember, N is the number of bits in a Blk.)
		q.blk[i] = 0;
		i2 = N;
		while (i2 > 0) {
			i2--;
			/*
			* Subtract b, shifted left i blocks and i2 bits, from *this,
			* and store the answer in subtractBuf.  In the for loop, `k == i + j'.
			*
			* Compare this to the middle section of `multiply'.  They
			* are in many ways analogous.  See especially the discussion
			* of `getShiftedBlock'.
			*/
			for (j = 0, k = i, borrowIn = false; j <= b.len; j++, k++) {
				temp = blk[k] - getShiftedBlock(b, j, i2);
				borrowOut = (temp > blk[k]);
				if (borrowIn) {
					borrowOut |= (temp == 0);
					temp--;
				}
				// Since 2005.01.11, indices of `subtractBuf' directly match those of `blk', so use `k'.
				subtractBuf[k] = temp; 
				borrowIn = borrowOut;
			}
			// No more extra iteration to deal with `bHigh'.
			// Roll-over a borrow as necessary.
			for (; k < origLen && borrowIn; k++) {
				borrowIn = (blk[k] == 0);
				subtractBuf[k] = blk[k] - 1;
			}
			/*
			* If the subtraction was performed successfully (!borrowIn),
			* set bit i2 in block i of the quotient.
			*
			* Then, copy the portion of subtractBuf filled by the subtraction
			* back to *this.  This portion starts with block i and ends--
			* where?  Not necessarily at block `i + b.len'!  Well, we
			* increased k every time we saved a block into subtractBuf, so
			* the region of subtractBuf we copy is just [i, k).
			*/
			if (!borrowIn) {
				q.blk[i] |= (Blk(1) << i2);
				while (k > i) {
					k--;
					blk[k] = subtractBuf[k];
				}
			} 
		}
	}
	// Zap possible leading zero in quotient
	if (q.blk[q.len - 1] == 0)
		q.len--;
	// Zap any/all leading zeros in remainder
	zapLeadingZeros();
	// Deallocate subtractBuf.
	// (Thanks to Brad Spencer for noticing my accidental omission of this!)
	delete [] subtractBuf;
}

/*
BigUnsigned modinv(const BigInteger &x, const BigUnsigned &n) {
	BigInteger g, r, s;
	extendedEuclidean(x, n, g, r, s);
	if (g == 1)
		// r*x + s*n == 1, so r*x === 1 (mod n), so r is the answer.
		return (r % n).getMagnitude(); // (r % n) will be nonnegative
	else
		throw "BigInteger modinv: x and n have a common factor";
}
*/

BigUnsigned modexp(const BigInteger &base, const BigUnsigned &exponent, const BigUnsigned &modulus) {
	BigUnsigned ans = 1, base2 = (base % modulus).getMagnitude();
	BigUnsigned::Index i = exponent.bitLength();
	// For each bit of the exponent, most to least significant...
	while (i > 0) {
		i--;
		// Square.
		ans *= ans;
		ans %= modulus;
		// And multiply if the bit is a 1.
		if (exponent.getBit(i)) {
			ans *= base2;
			ans %= modulus;
		}
	}
	return ans;
}



int encrypt(...) {



	return 0;
}
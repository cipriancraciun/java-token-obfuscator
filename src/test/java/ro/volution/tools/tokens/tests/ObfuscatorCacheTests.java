
package ro.volution.tools.tokens.tests;


import org.junit.Assert;
import org.junit.Test;

import ro.volution.tools.tokens.ObfuscatorCache;


public final class ObfuscatorCacheTests
			extends Object
{
	@Test
	public final void testSameCache () {
		final ObfuscatorCache<String> cache = ObfuscatorCache.create ();
		Assert.assertSame (cache.select ("a"), cache.select ("a"));
		Assert.assertNotSame (cache.select ("a"), cache.select ("b"));
	}
	
	@Test
	public final void testTwoCaches () {
		final ObfuscatorCache<String> cache_1 = ObfuscatorCache.create ();
		final ObfuscatorCache<String> cache_2 = ObfuscatorCache.create ();
		Assert.assertNotSame (cache_1.select ("a"), cache_2.select ("b"));
	}
}

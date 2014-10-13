
package ro.volution.tools.tokens;


import java.util.concurrent.ExecutionException;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;


public final class ObfuscatorCache<_Key_ extends Object>
{
	private ObfuscatorCache () {
		super ();
		this.cacheLoader = new CacheLoader<Object, Obfuscator> () {
			@Override
			public Obfuscator load (final Object key) {
				return (Obfuscator.create ());
			}
		};
		this.cache = CacheBuilder.newBuilder ().weakValues ().build (this.cacheLoader);
	}
	
	public final Obfuscator select (final _Key_ key) {
		try {
			return (this.cache.get (key));
		} catch (final ExecutionException error) {
			throw (new RuntimeException (error));
		}
	}
	
	private final LoadingCache<Object, Obfuscator> cache;
	private final CacheLoader<Object, Obfuscator> cacheLoader;
	
	public static final <_Key_ extends Object> ObfuscatorCache<_Key_> create () {
		return (new ObfuscatorCache<_Key_> ());
	}
}

package com.subgraph.orchid.data;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.subgraph.orchid.TorException;

public class RandomSet<E> {
	
	private final Set<E> set;
	private final List<E> list;
	private final SecureRandom random;
	
	public RandomSet() {
		set = new HashSet<E>();
		list = new ArrayList<E>();
		random = createRandom();
	}
	
	private static SecureRandom createRandom() {
		try {
			return SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			throw new TorException(e);
		}
	}
	
	public boolean add(E o) {
		if(set.add(o)) {
			list.add(o);
			return true;
		} else {
			return false;
		}
	}
	
	public boolean contains(Object o) {
		return set.contains(o);
	}
	
	public boolean isEmpty() {
		return set.isEmpty();
	}
	
	public void clear() {
		set.clear();
		list.clear();
	}
	
	public boolean remove(Object o) {
		if(set.remove(o)) {
			list.remove(o);
			return true;
		} else {
			return false;
		}
	}
	
	public int size() {
		return set.size();
	}
	
	public E getRandomElement() {
		int idx = random.nextInt(list.size());
		return list.get(idx);
	}

}

/**
 * Copyright 2014 James Jones
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.google.bitcoin.utils;

import java.util.Comparator;

import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.Utils;

/**
 * A comparator to evaluate and compare two keys alpha-numerically for ordering. 
 *
 */
public class KeyComparator implements Comparator<ECKey> {

	/**
	 * @throws RuntimeException if any one of the keys is not compressed
	 */
	@Override
	public int compare(ECKey k1, ECKey k2){
		
		if (!k1.isCompressed()||!k2.isCompressed()){
			throw new RuntimeException("Keys should be compressed for sorting.");
		}else{
			String k1Pub = Utils.bytesToHexString(k1.getPubKey());
			String k2Pub = Utils.bytesToHexString(k2.getPubKey());
			return k1Pub.compareTo(k2Pub);
		}
	}

}


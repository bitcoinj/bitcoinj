/*
 * Copyright by the original author or authors.
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

package org.bitcoinj.utils;

/**
 * Simple utility class, which supports with the destruction of 
 * security-relevant entities.
 * @author Nico Schmoigl
 *
 */
public class DestructionUtils {
	public static final byte BYTE_VALUE_USED_FOR_DESTRUCTION = 90; // arbitrary value
	
	/**
	 * destroys the contents of an arbitrary byte array (which contains security-relevant 
	 * data, such as a private key) to ensure that it cannot be abused by an attacker.
	 * @param subject the byte array, which shall be destroyed
	 */
	public static void destroyByteArray(byte[] subject) {
		if (subject == null) {
			return; // nothing to do
		}
		
		if (subject.length == 0) {
			return; // nothing to do
		}
		
		for (int i = 0; i<subject.length; i++) {
			subject[i] = BYTE_VALUE_USED_FOR_DESTRUCTION;
		}
	}
}

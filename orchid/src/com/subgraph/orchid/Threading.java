package com.subgraph.orchid;

import com.google.common.util.concurrent.CycleDetectingLockFactory;
import com.google.common.util.concurrent.ThreadFactoryBuilder;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Created by android on 8/22/14.
 */
public class Threading {
	static {
		// Default policy goes here. If you want to change this, use one of the static methods before
		// instantiating any orchid objects. The policy change will take effect only on new objects
		// from that point onwards.
		throwOnLockCycles();
	}

	private static CycleDetectingLockFactory.Policy policy;
	public static CycleDetectingLockFactory factory;

	public static ReentrantLock lock(String name) {
		return factory.newReentrantLock(name);
	}

	public static void warnOnLockCycles() {
		setPolicy(CycleDetectingLockFactory.Policies.WARN);
	}

	public static void throwOnLockCycles() {
		setPolicy(CycleDetectingLockFactory.Policies.THROW);
	}

	public static void ignoreLockCycles() {
		setPolicy(CycleDetectingLockFactory.Policies.DISABLED);
	}

	public static void setPolicy(CycleDetectingLockFactory.Policy policy) {
		Threading.policy = policy;
		factory = CycleDetectingLockFactory.newInstance(policy);
	}

	public static CycleDetectingLockFactory.Policy getPolicy() {
		return policy;
	}

	public static ExecutorService newPool(final String name) {
		ThreadFactory factory = new ThreadFactoryBuilder()
				.setDaemon(true)
				.setNameFormat(name + "-%d").build();
		return Executors.newCachedThreadPool(factory);
	}

	public static ScheduledExecutorService newSingleThreadScheduledPool(final String name) {
		ThreadFactory factory = new ThreadFactoryBuilder()
				.setDaemon(true)
				.setNameFormat(name + "-%d").build();
		return Executors.newSingleThreadScheduledExecutor(factory);
	}

	public static ScheduledExecutorService newScheduledPool(final String name) {
		ThreadFactory factory = new ThreadFactoryBuilder()
				.setDaemon(true)
				.setNameFormat(name + "-%d").build();
		return Executors.newScheduledThreadPool(1, factory);
	}
}

// Threads, a concurrent map, a lock and an exception, run by the JVM.
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.locks.ReentrantLock;

public class Threads {
    public static void main(String[] args) throws Exception {
        ConcurrentHashMap<Integer, Integer> squares = new ConcurrentHashMap<>();
        ExecutorService pool = Executors.newFixedThreadPool(4);
        List<Future<?>> done = new ArrayList<>();
        for (int i = 1; i <= 8; i++) {
            final int n = i;
            done.add(pool.submit(() -> squares.put(n, n * n)));
        }
        for (Future<?> f : done) f.get();
        pool.shutdown();
        System.out.println("squares " + new TreeMap<>(squares).values());
        ReentrantLock lock = new ReentrantLock();
        int[] total = {0};
        Thread[] threads = new Thread[4];
        for (int t = 0; t < 4; t++) {
            threads[t] = new Thread(() -> {
                for (int i = 0; i < 1000; i++) {
                    lock.lock();
                    try { total[0]++; } finally { lock.unlock(); }
                }
            });
            threads[t].start();
        }
        for (Thread t : threads) t.join();
        System.out.println("total " + total[0]);
        try {
            Object o = null;
            o.hashCode();
        } catch (NullPointerException e) {
            System.out.println("caught NullPointerException");
        }
        long sum = 0;
        for (int i = 0; i < 50_000_000; i++) sum += i % 7;
        System.out.println("sum " + sum);
    }
}

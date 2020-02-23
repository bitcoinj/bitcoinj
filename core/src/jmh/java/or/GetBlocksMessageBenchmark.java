package or;

import org.openjdk.jmh.annotations.*;
import org.bitcoinj.params.UnitTestParams;


public class GetBlocksMessageBenchmark {


    @org.openjdk.jmh.annotations.Benchmark
    @BenchmarkMode(Mode.All)
    @Warmup(iterations = 10)
    @Measurement(iterations = 10)
    public void test() throws IOException {
        NetworkParameters params = UnitTestParams.get();
        for (int i=0 ; i < 10 ; i++) {
            GetBlocksMessage Message = new GetBlocksMessage(params, i);
            Message.parse();
        }
    }
}

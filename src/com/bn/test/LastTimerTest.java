package com.bn.test;

class LastTimerTest {
    interface ITestJob {
        void run();
    }
    public void test(ITestJob work, long seconds, String mark){
        if(seconds <=0 ){
            throw new RuntimeException("params seconds must be positive.");
        }
        long start = System.currentTimeMillis();
        long count = 0, diff = 0;
        do{
            // test worker
            try {
                work.run();
            }catch (Throwable e){
                e.printStackTrace();
                throw new RuntimeException(String.format("[%s]-[NO.%d] test, with msg = [%s].", mark, count, e.toString()));
            }
            count++;
            diff = System.currentTimeMillis() - start;
        }while (diff < 1000 * seconds);
        System.out.println(String.format("[%s]: %s times test in total, and success.", mark, count));
    }
}

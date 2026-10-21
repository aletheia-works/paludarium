fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (a, b) = (
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                7
            }),
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                11
            }),
        );
        assert_eq!(a.await.unwrap() + b.await.unwrap(), 18);
    });
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    println!("timer:PASS");
}

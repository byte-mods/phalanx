use prometheus::{Registry, Counter};

fn main() {
    let r = Registry::new();
    let c = Counter::new("test", "test").unwrap();
    r.register(Box::new(c.clone())).unwrap();
    c.inc();
    
    for f in r.gather() {
        println!("name: {}", f.name());
        for m in f.metric() {
            println!("counter value: {:?}", m.counter().value());
        }
    }
}
